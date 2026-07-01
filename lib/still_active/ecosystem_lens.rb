# frozen_string_literal: true

require_relative "deps_dev_client"
require_relative "ecosystems_client"
require_relative "github_client"
require_relative "../helpers/activity_helper"
require_relative "../helpers/constraint_helper"
require_relative "../helpers/vulnerability_helper"

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
      cargo: "crates.io",
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

    def assess(ecosystem:, name:, version:, constraint_cache: {})
      info = DepsDevClient.version_info(gem_name: name, version: version, system: ecosystem)
      default = DepsDevClient.default_version_info(name: name, system: ecosystem)
      # Recover the repo from the default version when the exact locked version
      # isn't indexed (yanked/normalization mismatch): otherwise its project link
      # vanishes and a still-fresh package date would read a false :ok with
      # archived/scorecard silently dropped. The native Bundler path resolves the
      # repo independently of deps.dev's per-version record; this gives the lens
      # the same resilience.
      project_id = info&.dig(:project_id) || project_id_from(name, ecosystem, default)
      vulnerabilities = vulnerabilities_for(info)
      scorecard = DepsDevClient.project_scorecard(project_id: project_id)
      repo = repo_signals(project_id)

      gem_data = {
        ecosystem: ecosystem,
        name: name,
        version_used: version,
        latest_version_release_date: default&.dig(:published_at),
        repository_url: project_id && "https://#{project_id}",
        last_commit_date: repo[:last_commit_date],
        archived: repo[:archived],
        scorecard_score: scorecard&.dig(:score),
        scorecard_maintained: scorecard&.dig(:maintained),
        vulnerability_count: vulnerabilities.length,
        vulnerabilities: vulnerabilities,
      }
      attach_constraints(gem_data, ecosystem: ecosystem, name: name, version: version, cache: constraint_cache)
      gem_data
    end

    private

    # Poison-pill enrichment for the cross-ecosystem path, mirroring the native
    # Bundler path: gated on dormancy so a maintained package is never flagged,
    # each finding carrying its receipt. Resolves a capped dep's latest via
    # deps.dev in the SAME ecosystem (a runtime dep of an npm package is npm).
    def attach_constraints(gem_data, ecosystem:, name:, version:, cache:)
      registry = ECOSYSTEM_REGISTRIES[ecosystem]
      return if registry.nil?
      return unless FLAT_RESOLUTION_ECOSYSTEMS.include?(ecosystem)
      return unless [:critical, :archived].include?(ActivityHelper.activity_level(gem_data))

      declared = EcosystemsClient.declared_dependencies(name: name, version: version, registry: registry)
      findings = ConstraintHelper.poison_findings(declared) do |dep_name|
        latest_version_for(ecosystem, dep_name, cache)
      end
      return if findings.empty?

      gem_data[:constraints] = findings
      gem_data[:poison] = findings.any? { |finding| finding[:kind] == :ceiling }
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
      deps_dev = advisory_keys.map { DepsDevClient.advisory_detail(advisory_id: _1) || { id: _1, source: "deps.dev" } }
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
  end
end
