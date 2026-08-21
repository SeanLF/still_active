# frozen_string_literal: true

require_relative "deps_dev_client"
require_relative "osv_client"
require_relative "ecosystems_client"
require_relative "github_client"
require_relative "pypi_client"
require "time"
require_relative "helpers/activity_helper"
require_relative "helpers/constraint_helper"
require_relative "helpers/dotnet_helper"
require_relative "helpers/libyear_helper"
require_relative "helpers/pep440_helper"
require_relative "helpers/runtime_ceiling_helper"
require_relative "helpers/version_helper"
require_relative "helpers/vulnerability_helper"

module StillActive
  # The cross-ecosystem maintenance lens. Given one SBOM-derived dependency
  # ({ecosystem, name, version}), it assembles the same maintenance signals the
  # native Ruby path produces -- latest release date, archived, advisories,
  # scorecard -- into a gem_data hash StatusHelper.gem_status can read directly.
  # The breadth counterpart to the depth Bundler path gives Ruby.
  #
  # Security: the SBOM supplies only ecosystem/name/version. The repository is
  # discovered from deps.dev (a public source still_active opts into), never from
  # a lockfile-derived URL, so a hostile SBOM can't redirect a lookup. Anything
  # unresolvable (a private package deps.dev doesn't index) degrades to nil
  # signals -> :unknown, never a fabricated "ok".
  module EcosystemLens
    extend self

    # still_active ecosystem symbol -> ecosyste.ms registry name for the declared
    # dependency (poison-pill) lookup. Only the ecosystems where the ecosyste.ms
    # registry name and the deps.dev package name align cleanly are wired; maven
    # (group:artifact) and go (module paths) need name-format handling and are
    # left out for now, so they simply carry no constraint signal rather than a
    # wrong one.
    ECOSYSTEM_REGISTRIES = {
      rubygems: "rubygems.org",
      npm: "npmjs.org",
      pypi: "pypi.org",
      cargo: "crates.io"
    }.freeze

    # A transitive cap only holds the WHOLE tree hostage where the ecosystem
    # forces one version per package. Ruby/Bundler and pip do (flat resolution);
    # npm nests multiple versions and cargo coexists majors, so a below-latest cap
    # there pins a duplicate copy in one subtree -- not a tree-wide block. The one
    # npm case that DOES block (peerDependencies / de-facto singletons) isn't
    # visible in ecosyste.ms data (its parser drops peerDependencies), so emitting
    # poison for npm/cargo would over-claim on the non-blocking cases and miss the
    # blocking ones. Suppress it there until peer requirements are sourced from
    # deps.dev; silence beats a false "holds your tree hostage".
    FLAT_RESOLUTION_ECOSYSTEMS = [:rubygems, :pypi].freeze

    def assess(ecosystem:, name:, version:, constraint_cache: {}, runtime_ranges: {})
      info = DepsDevClient.version_info(gem_name: name, version: version, system: ecosystem)
      default = DepsDevClient.default_version_info(name: name, system: ecosystem)
      # Retry the version lookup once when it came back empty but the package DID
      # resolve: HttpHelper collapses a genuine 404 and a transient network blip to
      # the same nil, and a healthy version must not be mis-flagged as unresolved
      # (below) on a one-off miss. A real 404 stays nil; a blip recovers the data.
      info ||= DepsDevClient.version_info(gem_name: name, version: version, system: ecosystem) if default
      # Recover the repo from the default version when the exact locked version
      # isn't indexed (yanked/normalization mismatch): otherwise its project link
      # vanishes and a still-fresh package date would read a false :ok with
      # archived/scorecard silently dropped. The native Bundler path resolves the
      # repo independently of deps.dev's per-version record; this gives the lens
      # the same resilience.
      # The pinned version isn't indexed by deps.dev (info nil) while the package IS
      # (default present, so the feed is up): the version is yanked/nonexistent, not a
      # transient miss. Flag it so status reads :unknown rather than letting the still-
      # fresh PACKAGE date report a nonexistent version as :ok.
      version_unresolved = info.nil? && !default.nil?
      project_id = info&.dig(:project_id) || project_id_from(name, ecosystem, default)
      vulnerabilities = vulnerabilities_for(info)
      # Enrich with OSV: a real GHSA severity label (deps.dev can't score a CVSS-4-only
      # advisory) and the fixed-version ranges the "capped below the fix" signal needs.
      # Passing the version also lets OSV confirm the advisory actually applies to it,
      # correcting deps.dev's lag on an advisory amended with backport fixes.
      vulnerabilities = OsvClient.enrich(vulnerabilities, ecosystem: ecosystem, name: name, version: version)
      scorecard = DepsDevClient.project_scorecard(project_id: project_id)
      repo = repo_signals(project_id)

      used_release_date = info&.dig(:published_at)
      latest_release_date = default&.dig(:published_at)
      latest_version = default&.dig(:version)
      gem_data = {
        ecosystem: ecosystem,
        name: name,
        version_used: version,
        version_used_release_date: used_release_date,
        # The latest stable version string, so the shared formatters can render
        # the "behind X"/up-to-date delta cross-ecosystem the same way the native
        # path does. nil when deps.dev has no default version for the package.
        latest_version: latest_version,
        latest_version_release_date: latest_release_date,
        # libyear parity with the native path: how far behind latest the locked
        # version is, in release-years. Both dates come from deps.dev responses
        # already fetched above (no extra call); nil when either date is missing.
        libyear: LibyearHelper.gem_libyear(
          version_used_release_date: parse_time(used_release_date),
          latest_version_release_date: parse_time(latest_release_date)
        ),
        # Whether the pinned version is at or ahead of deps.dev's latest stable, so a
        # prerelease or an ahead-of-stable pin reads current (true), not "behind" --
        # parity with the native path's `>=` comparison. nil when latest is unknown.
        up_to_date: version_current?(version, latest_version),
        # The pinned version's licence, rendered exactly as the native path renders
        # it (VersionHelper does the joining for both). It rides along in the
        # version response already fetched above, so this is no extra call. nil when
        # the package declares none, never a blank string.
        license: VersionHelper.format_licenses(info&.dig(:licenses)),
        repository_url: project_id && "https://#{project_id}",
        last_commit_date: repo[:last_commit_date],
        archived: repo[:archived],
        scorecard_score: scorecard&.dig(:score),
        scorecard_maintained: scorecard&.dig(:maintained),
        vulnerability_count: vulnerabilities.length,
        vulnerabilities: vulnerabilities
      }
      gem_data[:version_unresolved] = true if version_unresolved
      attach_constraints(gem_data, ecosystem: ecosystem, name: name, version: version, cache: constraint_cache)
      attach_language_ceiling(gem_data, ecosystem: ecosystem, name: name, version: version, latest_version: default&.dig(:version), runtime_ranges: runtime_ranges)
      gem_data
    end

    private

    # Language-runtime ceiling for the cross-ecosystem path, the sibling of the
    # native Ruby ceiling in Workflow. Python declares its runtime constraint as a
    # PEP 440 `requires_python`, an enforced pip install wall; translate it and run
    # the same generic RuntimeCeilingHelper against Python's support window. Unlike
    # poison this is NOT gated on dormancy (a cap is a fact of the resolved version
    # whether or not the package is maintained), so it costs one PyPI read per
    # pypi package; other ecosystems carry no ceiling here rather than a wrong one
    # (cargo's rust_version is a soft MSRV hint, not an install wall). Best-effort:
    # a nil range (endoflife feed down) or absent requires_python yields nothing.
    def attach_language_ceiling(gem_data, ecosystem:, name:, version:, latest_version:, runtime_ranges:)
      finding =
        case ecosystem
        when :pypi then python_ceiling(name: name, version: version, latest_version: latest_version, python_range: runtime_ranges[:python])
        when :nuget then dotnet_ceiling(name: name, version: version, latest_version: latest_version, dotnet: runtime_ranges[:dotnet], dotnetfx: runtime_ranges[:dotnetfx])
        end
      gem_data[:language_ceiling] = finding if finding
    end

    def python_ceiling(name:, version:, latest_version:, python_range:)
      return if python_range.nil?

      requirement = Pep440Helper.to_gem_requirement_string(PypiClient.requires_python(name: name, version: version))
      finding = requirement && RuntimeCeilingHelper.analyze(requirement: requirement, support_window: python_range)
      return if finding.nil?

      finding[:runtime] = "Python"
      finding[:fixed_by_upgrade] = python_ceiling_lifted_by_upgrade?(name: name, version: version, latest_version: latest_version, python_range: python_range)
      finding
    end

    # The .NET ceiling: a NuGet package whose ONLY runtime targets are end-of-life
    # frameworks caps you onto a dead runtime (a restore-time NU1202 wall). Unlike
    # Python's requires_python range, .NET declares a SET of target frameworks;
    # DotnetHelper carries the set logic and the netstandard escape-hatch rule.
    def dotnet_ceiling(name:, version:, latest_version:, dotnet:, dotnetfx:)
      return if dotnet.nil? && dotnetfx.nil?

      frameworks = DepsDevClient.target_frameworks(name: name, version: version)
      return if frameworks.empty?

      finding = DotnetHelper.analyze(target_frameworks: frameworks, dotnet: dotnet, dotnetfx: dotnetfx)
      return if finding.nil?

      finding[:fixed_by_upgrade] = dotnet_ceiling_lifted_by_upgrade?(name: name, version: version, latest_version: latest_version, dotnet: dotnet, dotnetfx: dotnetfx)
      finding
    end

    # Positive confirmation, like the Python check: only claim an upgrade lifts the
    # ceiling when the latest version's targets ACTUALLY clear it (a fresh fetch),
    # never inferring "safe to bump" from a failed lookup.
    def dotnet_ceiling_lifted_by_upgrade?(name:, version:, latest_version:, dotnet:, dotnetfx:)
      return false if latest_version.nil? || latest_version == version

      latest_frameworks = DepsDevClient.target_frameworks(name: name, version: latest_version)
      return false if latest_frameworks.empty?

      DotnetHelper.analyze(target_frameworks: latest_frameworks, dotnet: dotnet, dotnetfx: dotnetfx).nil?
    end

    # Does upgrading the package to its latest release lift the cap? Requires
    # POSITIVE confirmation, unlike the native ruby_ceiling_lifted_by_upgrade?
    # whose latest requirement is read from data already in hand. Here the latest
    # requires_python is a fresh PyPI read, and PypiClient returns nil for BOTH
    # "declares no constraint" AND "the fetch failed" -- indistinguishable. Reading
    # that nil as "no ceiling, safe to bump" would fabricate remediation on a
    # transient PyPI error, the exact over-claim this tool must never make. So a
    # nil specifier yields false (we don't advise an upgrade we couldn't verify);
    # only a readable constraint that analyze confirms is non-capping lifts it.
    def python_ceiling_lifted_by_upgrade?(name:, version:, latest_version:, python_range:)
      return false if latest_version.nil? || latest_version == version

      latest_specifier = PypiClient.requires_python(name: name, version: latest_version)
      return false if latest_specifier.nil?

      latest_requirement = Pep440Helper.to_gem_requirement_string(latest_specifier)
      RuntimeCeilingHelper.analyze(requirement: latest_requirement, support_window: python_range).nil?
    end

    # Constraint enrichment for the cross-ecosystem path, gated on dormancy so a
    # maintained package is never flagged. Two shapes by ecosystem:
    #
    # FLAT (rubygems/pypi): the poison-pill signal as-is -- a below-latest cap holds
    # the whole tree hostage, so it renders directly (`constraints` + `poison`).
    #
    # NESTED (npm/cargo): the pure below-latest cap is subtree-local noise (nested
    # copies, caret default), so no poison here. Instead keep every declared dep as a
    # security CANDIDATE (`capped_deps`); the correlator, which alone sees the tree's
    # resolved versions and advisories, promotes only the ones that pin a vulnerable
    # copy below its fix. Candidates are NOT filtered to below-latest-major (npm/cargo
    # fixes are mostly same-major patch bumps that filter would miss) and need no
    # dep_latest fetch (the wall test is patch-precise on the requirement itself).
    def attach_constraints(gem_data, ecosystem:, name:, version:, cache:)
      registry = ECOSYSTEM_REGISTRIES[ecosystem]
      return if registry.nil?
      return unless [:critical, :archived].include?(ActivityHelper.activity_level(gem_data))

      declared = EcosystemsClient.declared_dependencies(name: name, version: version, registry: registry)
      if FLAT_RESOLUTION_ECOSYSTEMS.include?(ecosystem)
        attach_flat_poison(gem_data, ecosystem, declared, cache)
      else
        attach_nested_candidates(gem_data, declared)
      end
    end

    def attach_flat_poison(gem_data, ecosystem, declared, cache)
      findings = ConstraintHelper.poison_findings(declared) do |dep_name|
        latest_version_for(ecosystem, dep_name, cache)
      end
      return if findings.empty?

      gem_data[:constraints] = findings
      gem_data[:poison] = findings.any? { |finding| finding[:kind] == :ceiling }
      gem_data[:poison_severity] = ConstraintHelper.worst_severity(findings) if gem_data[:poison]
    end

    def attach_nested_candidates(gem_data, declared)
      candidates = declared.filter_map do |dep|
        next if dep[:package_name].to_s.empty? || dep[:requirements].to_s.empty?

        {dependency: dep[:package_name], requirement: dep[:requirements]}
      end
      gem_data[:capped_deps] = candidates unless candidates.empty?
    end

    # A capped dep's current latest version in `ecosystem`, via deps.dev's default
    # (latest stable) version. Memoized per run, keyed by ecosystem+name so an npm
    # `foo` and a pypi `foo` never collide. Only a RESOLVED version is cached: a
    # nil can mean "genuinely unindexed" or "deps.dev was momentarily down / rate-
    # limited" (both surface as nil here), and caching the transient case would
    # suppress the pill for every later dormant package capping the same dep. So an
    # unresolved dep is re-attempted rather than remembered as a permanent miss.
    def latest_version_for(ecosystem, dep_name, cache)
      key = "#{ecosystem}/#{dep_name}"
      cache[key] ||= DepsDevClient.default_version_info(name: dep_name, system: ecosystem)&.dig(:version)
    end

    def vulnerabilities_for(info)
      advisory_keys = info&.dig(:advisory_keys) || []
      # The keys ARE the evidence the locked version is vulnerable; the detail
      # fetch only enriches CVSS/title. A failed enrichment must not drop the
      # count to zero and read a known-vulnerable dep as clean, so a key whose
      # detail can't be loaded still contributes a minimal advisory.
      deps_dev = advisory_keys.map { DepsDevClient.advisory_detail(advisory_id: _1) || {id: _1, source: "deps.dev"} }
      # No ruby-advisory-db here: that database is Ruby-only and the native
      # Bundler path already merges it. Cross-ecosystem advisories come from
      # deps.dev/OSV, which covers every system the lens serves.
      VulnerabilityHelper.merge_advisories(deps_dev: deps_dev, ruby_advisory_db: [])
    end

    # The repo project_id from the package's default version, used only when the
    # locked version's deps.dev record is missing or carries no link.
    def project_id_from(name, ecosystem, default)
      version = default&.dig(:version)
      return if version.nil?

      DepsDevClient.version_info(gem_name: name, version: version, system: ecosystem)&.dig(:project_id)
    end

    # archived + last-commit for a flat github.com/owner/repo project, or {} for
    # anything else. deps.dev indexes github.com and gitlab.com only, but gitlab
    # subgroups nest arbitrarily and ecosyste.ms's repo crawler is GitHub-centric,
    # so a gitlab (or nested, or unresolved) project keeps archived unknown rather
    # than risk a bogus owner/name lookup.
    def repo_signals(project_id)
      host, owner, name, *rest = project_id.to_s.split("/")
      return {} unless host == "github.com" && owner && name && rest.empty?

      repo_provider.repo_signals(owner: owner, name: name) || {}
    end

    # Mirrors Workflow#provider_for(:github): the live GitHub API when a token is
    # configured (freshest), else ecosyste.ms (5000 anonymous req/hr vs GitHub's
    # 60), so an untokened cross-ecosystem run still resolves a large SBOM.
    def repo_provider
      StillActive.config.github_oauth_token ? GithubClient : EcosystemsClient
    end

    # Is the pinned version at or ahead of latest stable? nil when latest is unknown.
    # Gem::Version handles semver prereleases (`16.3.0-canary.7` sorts as a prerelease
    # of 16.3.0, so ahead of a 16.2.x stable -> current), so a beta/ahead pin reads
    # true, not "behind". Versions Gem::Version can't parse (pypi epoch `1!2.3`, build
    # metadata, a `v` prefix) fall back to exact match -- ahead reads false there, the
    # safe direction, and libyear still carries the real magnitude.
    def version_current?(version, latest)
      return false if latest.nil?
      return version == latest unless Gem::Version.correct?(version) && Gem::Version.correct?(latest)

      Gem::Version.new(version) >= Gem::Version.new(latest)
    end

    # deps.dev renders dates as ISO8601 strings; libyear needs Time to subtract.
    # nil-safe, and a malformed value degrades to nil rather than raising.
    def parse_time(value)
      # Guard the type, not just nil: a non-String publishedAt (schema drift) would
      # make Time.parse raise TypeError (unrescued) and, since this enrichment runs
      # in assess, demote an otherwise-healthy package. Best-effort must degrade.
      return unless value.is_a?(String)

      Time.parse(value)
    rescue ArgumentError
      nil
    end
  end
end
