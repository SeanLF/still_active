# frozen_string_literal: true

require_relative "artifactory_client"
require_relative "compact_index_client"
require_relative "source_credentials"
require_relative "ceiling_reconciler"
require_relative "deps_dev_client"
require_relative "osv_client"
require_relative "poison_security_correlator"
require_relative "ecosystems_client"
require_relative "forgejo_client"
require_relative "github_client"
require_relative "gitlab_client"
require_relative "repository"
require_relative "../helpers/activity_helper"
require_relative "../helpers/alternatives_helper"
require_relative "../helpers/catalog_index"
require_relative "../helpers/constraint_helper"
require_relative "../helpers/http_helper"
require_relative "../helpers/libyear_helper"
require_relative "../helpers/ruby_advisory_db"
require_relative "../helpers/ruby_helper"
require_relative "../helpers/runtime_ceiling_helper"
require_relative "../helpers/version_helper"
require_relative "../helpers/vulnerability_helper"
require "async"
require "async/barrier"
require "async/semaphore"
require "cgi"
require "gems"

module StillActive
  module Workflow
    extend self

    def call(&on_progress)
      task = Async do
        # Load the optional ruby-advisory-db once, before the fan-out, so the
        # read-only Database is shared across fibers rather than reloaded per gem.
        advisory_db = RubyAdvisoryDb.load
        catalog = StillActive.config.alternatives ? CatalogIndex.load : nil
        # The Ruby support window (oldest-supported / latest-stable / EOL cycles)
        # is a per-run constant, so fetch it once here rather than per gem. nil when
        # the endoflife feed is unavailable -> the language-ceiling signal quietly
        # sits out, exactly like a missing advisory_db. This runs OUTSIDE the
        # per-gem rescue, so a defensive rescue keeps a best-effort enrichment from
        # ever aborting the whole audit (the "never crash the core" contract).
        ruby_range =
          begin
            RubyHelper.supported_ruby_range
          rescue => e
            warn("warning: Ruby support window lookup failed: #{e.class} (#{e.message}); skipping language-ceiling checks")
            nil
          end
        # Resolve the GitHub token once here, single-fibered, before the fan-out:
        # provider_for reads it per gem across fibers and gh_cli_token shells out,
        # so resolving eagerly keeps that off the concurrent path and guarantees
        # every fiber sees one consistent value (token -> live GitHub, incl. private
        # repos; only a genuinely absent token falls back to ecosyste.ms).
        StillActive.config.github_oauth_token
        barrier = Async::Barrier.new
        semaphore = Async::Semaphore.new(StillActive.config.parallelism, parent: barrier)
        result_object = {}
        # Memoizes each capped dep's latest version across gems for the run, so a
        # dep pinned by several dormant gems is resolved once. Shared, single-writer
        # under Async's cooperative scheduling (a duplicate concurrent miss just
        # refetches the same value; it can't corrupt the map).
        constraint_cache = {}
        total = StillActive.config.gems.size
        completed = 0
        StillActive.config.gems.each_with_object(result_object) do |gem, hash|
          semaphore.async do
            gem_info(
              gem_name: gem[:name],
              result_object: hash,
              gem_version: gem[:version],
              source_type: gem[:source_type] || :rubygems,
              source_uri: gem[:source_uri],
              direct: gem.fetch(:direct, true),
              dependency_path: gem[:dependency_path],
              advisory_db: advisory_db,
              catalog: catalog,
              constraint_cache: constraint_cache,
              ruby_range: ruby_range
            )
          rescue Octokit::TooManyRequests
            $stderr.print("\r\e[K") if on_progress
            warn("rate limited checking #{gem[:name]}: set GITHUB_TOKEN to increase your limit")
          rescue => e
            $stderr.print("\r\e[K") if on_progress
            warn("error occurred for #{gem[:name]}: #{e.class}\n\t#{e.message}")
          ensure
            completed += 1
            on_progress&.call(completed, total)
          end
        end
        barrier.wait
        # Whole-tree correlation, once every gem's signals are in: a ceiling's
        # "upgrade to lift it" must not contradict a poison finding that caps the
        # same gem below that upgrade.
        CeilingReconciler.reconcile_ceiling_with_poison(result_object)
        # Flag poison caps that pin a vulnerable dependency: "a dormant package is
        # holding you on a known-vulnerable dep, below the fix." No extra fetches.
        PoisonSecurityCorrelator.correlate(result_object)
        # Gems are inserted as their async tasks finish, so the natural order is
        # nondeterministic completion order. Sort by name once here so every
        # consumer (JSON, SARIF, the baseline diff) gets a stable, diffable order.
        result_object.sort_by { |name, _| name }.to_h
      end
      task.wait
    end

    def ruby_freshness
      RubyHelper.ruby_freshness
    end

    private

    def gem_info(gem_name:, result_object:, gem_version: nil, source_type: :rubygems, source_uri: nil, direct: true, dependency_path: nil, advisory_db: nil, catalog: nil, constraint_cache: {}, ruby_range: nil)
      result_object[gem_name] = {source_type: source_type, direct: direct}
      result_object[gem_name][:dependency_path] = dependency_path if dependency_path
      result_object[gem_name][:version_used] = gem_version if gem_version

      case source_type
      when :path, :git
        gem_info_non_rubygems(gem_name: gem_name, gem_version: gem_version, result_object: result_object, source_uri: source_uri, advisory_db: advisory_db)
      else
        gem_info_rubygems(
          gem_name: gem_name,
          gem_version: gem_version,
          result_object: result_object,
          source_uri: source_uri,
          advisory_db: advisory_db,
          ruby_range: ruby_range
        )
      end

      attach_alternatives(gem_name: gem_name, result_object: result_object, catalog: catalog)
      # Poison-pill enrichment runs last and only on the rubygems path (git/path
      # gems aren't in the registry). Placed after alternatives so a stray fetch
      # error can never cost the gem its other, already-assembled signals.
      unless [:path, :git].include?(source_type)
        attach_constraints(gem_name: gem_name, result_object: result_object, cache: constraint_cache)
      end
    end

    def gem_info_rubygems(gem_name:, gem_version:, result_object:, source_uri:, advisory_db: nil, ruby_range: nil)
      vs = versions(gem_name: gem_name, source_uri: source_uri)
      repo_info = repository_info(gem_name: gem_name, versions: vs, source_uri: source_uri)
      signals = repo_signals(
        source: repo_info[:source],
        repository_owner: repo_info[:owner],
        repository_name: repo_info[:name]
      )
      commit_date = signals[:last_commit_date]
      archived = signals[:archived]
      last_release = VersionHelper.find_version(versions: vs, pre_release: false)
      last_pre_release = VersionHelper.upcoming_pre_release(
        pre_release: VersionHelper.find_version(versions: vs, pre_release: true),
        release: last_release
      )
      deps_dev = fetch_deps_dev_info(
        gem_name: gem_name,
        version: gem_version || VersionHelper.gem_version(version_hash: last_release),
        advisory_db: advisory_db
      )
      result_object[gem_name].merge!({
        latest_version: VersionHelper.gem_version(version_hash: last_release),
        latest_version_release_date: VersionHelper.release_date(version_hash: last_release),

        latest_pre_release_version: VersionHelper.gem_version(version_hash: last_pre_release),
        latest_pre_release_version_release_date: VersionHelper.release_date(version_hash: last_pre_release),

        repository_url: repo_info[:url],
        last_commit_date: commit_date,
        archived: archived,
        **deps_dev
      })

      # Only a gem that actually lives on public rubygems.org gets a rubygems.org
      # page link. For a private source, rubygems.org/gems/<name> is a public
      # name collision (for sidekiq-pro, the 0.0.3 squat-warning decoy), not the
      # gem the user resolves -- the same #43 substitution the repo-URL guard blocks.
      unless vs.empty? || unqueryable_private_source?(source_uri)
        result_object[gem_name][:ruby_gems_url] = "https://rubygems.org/gems/#{gem_name}"
      end

      if StillActive.config.unreleased_commits
        result_object[gem_name][:unreleased_commits] = unreleased_commits(
          source: repo_info[:source],
          repository_owner: repo_info[:owner],
          repository_name: repo_info[:name],
          version: VersionHelper.gem_version(version_hash: last_release)
        )
      end

      version_used = gem_version ? VersionHelper.find_version(versions: vs, version_string: gem_version) : nil
      if gem_version
        result_object[gem_name].merge!({
          up_to_date: VersionHelper.up_to_date(
            version_used: version_used,
            latest_version: last_release,
            latest_pre_release_version: last_pre_release
          ),

          version_used_release_date: VersionHelper.release_date(version_hash: version_used),
          version_yanked: !vs.empty? && version_used.nil?,
          license: VersionHelper.license(version_hash: version_used),
          libyear: LibyearHelper.gem_libyear(
            version_used_release_date: VersionHelper.release_date(version_hash: version_used),
            latest_version_release_date: VersionHelper.release_date(version_hash: last_release)
          )
        })
      end

      # A version pinned to a now-yanked release has no resolvable ruby_version to
      # judge, and `pinned: !version_used.nil?` would otherwise fall through to the
      # latest version's cap and attach IT to the locked gem -- a false ceiling on a
      # version we can't actually read. Skip; the yanked lock is already flagged.
      yanked_lock = !gem_version.nil? && version_used.nil? && !vs.empty?
      unless yanked_lock
        attach_ruby_ceiling(
          gem_data: result_object[gem_name],
          used_ruby_requirement: canonical_ruby_requirement(vs, version_used),
          latest_ruby_requirement: canonical_ruby_requirement(vs, last_release),
          pinned: !version_used.nil?,
          ruby_range: ruby_range
        )
      end
    end

    # The ruby_version to judge a language ceiling against, read from the canonical
    # `ruby` (source) platform entry of a version rather than whichever variant the
    # registry happens to list first. Native gems ship a permissive `ruby` platform
    # plus precompiled per-platform variants that cap ruby_version to the ABIs they
    # were built for; the source platform is the gem's true Ruby support (it can be
    # compiled on a newer Ruby), so a precompiled variant's tighter cap must not be
    # read as the gem's ceiling. (Flagging that a project's LOCKED precompiled
    # variant lacks a newer-Ruby build is a distinct, narrower signal, and needs the
    # locked platform, which isn't threaded here yet.)
    def canonical_ruby_requirement(versions, version_hash)
      number = version_hash && version_hash["number"]
      return if number.nil?

      entries = versions.select { |version| version["number"] == number }
      chosen = entries.find { |version| version["platform"] == "ruby" || version["platform"].nil? } || entries.first
      VersionHelper.ruby_requirement(version_hash: chosen)
    end

    # Language-runtime ceiling: the sibling of poison. A gem's resolved version
    # declares a `ruby_version` that caps the runtime -- either onto an end-of-life
    # Ruby (critical: no patched runtime is reachable) or below the latest stable
    # (note: a compatibility ceiling to plan around / a place to contribute Ruby-N
    # support). Unlike poison this is NOT gated on dormancy: a cap is a fact of the
    # resolved version whether or not the gem is maintained. Best-effort: a nil
    # range (endoflife feed down) or absent ruby_version yields no finding.
    def attach_ruby_ceiling(gem_data:, used_ruby_requirement:, latest_ruby_requirement:, pinned:, ruby_range:)
      return if ruby_range.nil?

      # Analyze the version actually in the tree. Fall back to latest ONLY when
      # there's no pinned version (a latest-only audit), never when the pinned
      # version merely declares no ruby_version: an absent cap runs on any Ruby, so
      # projecting a newer release's cap back onto it would mint a false ceiling.
      requirement = pinned ? used_ruby_requirement : latest_ruby_requirement
      finding = RuntimeCeilingHelper.analyze(requirement: requirement, support_window: ruby_range)
      return if finding.nil?

      finding[:fixed_by_upgrade] = ruby_ceiling_lifted_by_upgrade?(used_req: used_ruby_requirement, latest_req: latest_ruby_requirement, ruby_range: ruby_range)
      # The runtime this cap is against, so the shared renderers (terminal, md,
      # SARIF) name it without hardcoding "Ruby". The Python SBOM path attaches the
      # same shape with runtime "Python"; everything downstream is runtime-neutral.
      finding[:runtime] = "Ruby"
      gem_data[:language_ceiling] = finding
    end

    # Does bumping the gem to its latest lift the ceiling? True only when the cap
    # is on the resolved (older) version and the latest version declares no ceiling
    # of its own -- the actionable "upgrade the gem" case (e.g. CFPropertyList
    # 3.0.9's `< 3.2` cap, gone by 4.0.0). False when already on latest.
    def ruby_ceiling_lifted_by_upgrade?(used_req:, latest_req:, ruby_range:)
      return false if used_req.nil? || used_req == latest_req

      RuntimeCeilingHelper.analyze(requirement: latest_req, support_window: ruby_range).nil?
    end

    def gem_info_non_rubygems(gem_name:, gem_version:, result_object:, source_uri: nil, advisory_db: nil)
      repo_info = repository_info_for_non_rubygems(gem_name: gem_name, source_uri: source_uri)
      source, owner, name = repo_info.values_at(:source, :owner, :name)
      deps_dev = gem_version ? fetch_deps_dev_info(gem_name: gem_name, version: gem_version, advisory_db: advisory_db) : {}

      # Fall back to repo-derived project_id for scorecard when deps.dev doesn't
      # have the version. Use ||= so a maintained score already found via the
      # version's scorecard is never clobbered by a nil from the repo fallback
      # (0.0 is truthy, so a measured "unmaintained" is preserved too).
      if deps_dev[:scorecard_score].nil?
        fallback = DepsDevClient.project_scorecard(project_id: repo_info[:project_id])
        deps_dev[:scorecard_score] ||= fallback&.dig(:score)
        deps_dev[:scorecard_maintained] ||= fallback&.dig(:maintained)
      end

      signals = repo_signals(source:, repository_owner: owner, repository_name: name)
      result_object[gem_name].merge!({
        repository_url: repo_info[:url],
        last_commit_date: signals[:last_commit_date],
        archived: signals[:archived],
        **deps_dev
      })
    end

    def attach_alternatives(gem_name:, result_object:, catalog:)
      return if catalog.nil?
      # Direct-only by design: "replace gem X with better-maintained Y" is
      # incoherent for a transitive gem the user never chose (#60). The
      # path-to-parent points them at the direct gem they can actually swap.
      return unless result_object[gem_name][:direct]
      return unless [:archived, :critical].include?(ActivityHelper.activity_level(result_object[gem_name]))

      leads = AlternativesHelper.leads_for(gem_name: gem_name, index: catalog)
      result_object[gem_name][:alternatives] = leads unless leads.empty?
    rescue
      nil # cosmetic best-effort: lead-fetching must never break the core audit
    end

    # Poison-pill detection. A dormant gem that declares a runtime constraint
    # capping a still-evolving dep BELOW that dep's current latest major holds the
    # tree hostage: the cap will never lift because nobody is shipping the gem, and
    # it gets more poisonous with time as the capped dep keeps releasing majors.
    #
    # Gated on dormancy so a MAINTAINED gem with a cap is never flagged (it'll bump
    # the cap) -- that gate is the whole discipline of the signal. Each surviving
    # finding carries its receipt (caps X; latest Y; N majors behind). Best-effort
    # and non-raising: every underlying call degrades to []/nil on failure, so a
    # lookup miss just means "no constraints known", never a dropped gem.
    def attach_constraints(gem_name:, result_object:, cache:)
      gem_data = result_object[gem_name]
      # The locked version if the caller pinned one (that's the requirement set
      # actually in their tree), else the gem's latest.
      version = gem_data[:version_used] || gem_data[:latest_version]
      return if version.nil?
      return unless [:critical, :archived].include?(ActivityHelper.activity_level(gem_data))

      declared = EcosystemsClient.declared_dependencies(name: gem_name, version: version)
      constraints = ConstraintHelper.poison_findings(declared) do |dep_name|
        resolve_latest_version(dep_name, result_object: result_object, cache: cache)
      end
      return if constraints.empty?

      gem_data[:constraints] = constraints
      # Poison = a version ceiling that blocks upgrades. An exact-pin below latest
      # is a milder resolution hazard: still surfaced in constraints, but it may be
      # deliberate, so it doesn't earn the poison label on its own.
      gem_data[:poison] = constraints.any? { |constraint| constraint[:kind] == :ceiling }
      gem_data[:poison_severity] = ConstraintHelper.worst_severity(constraints) if gem_data[:poison]
    end

    # The capped dep's current latest stable version, for the majors-behind math.
    # Reuse the tree's already-computed latest_version when the dep is itself in
    # the audit (no extra request); otherwise fetch and memoize per run, so a dep
    # capped by several dormant gems is looked up once. Only a RESOLVED version is
    # cached: an unresolved lookup returns nil whether the dep is genuinely absent
    # or rubygems.org was momentarily rate-limited, and caching the transient case
    # would drop the pill for every later gem capping the same dep. So a miss is
    # re-attempted rather than remembered.
    def resolve_latest_version(dep_name, result_object:, cache:)
      cache[dep_name] ||= result_object[dep_name]&.dig(:latest_version) || fetch_latest_version(dep_name)
    end

    def fetch_latest_version(dep_name)
      latest = VersionHelper.find_version(versions: versions(gem_name: dep_name), pre_release: false)
      VersionHelper.gem_version(version_hash: latest)
    end

    def fetch_deps_dev_info(gem_name:, version:, advisory_db: nil)
      info = DepsDevClient.version_info(gem_name: gem_name, version: version)
      scorecard = DepsDevClient.project_scorecard(project_id: info&.dig(:project_id))
      advisory_keys = info&.dig(:advisory_keys) || []
      # The keys ARE the evidence the version is vulnerable; the detail fetch only
      # enriches CVSS/title. A failed enrichment (429/timeout/5xx -> nil) must not
      # drop the advisory and read a known-vulnerable gem as clean, so an
      # un-enriched key still contributes a minimal advisory (mirrors EcosystemLens;
      # ruby-advisory-db then fills the score on merge when it also carries it).
      deps_dev_vulns = advisory_keys.map { |id| DepsDevClient.advisory_detail(advisory_id: id) || {id: id, source: "deps.dev"} }
      radb_vulns = RubyAdvisoryDb.advisories_for(database: advisory_db, gem_name: gem_name, version: version)
      vulnerabilities = VulnerabilityHelper.merge_advisories(deps_dev: deps_dev_vulns, ruby_advisory_db: radb_vulns)
      # Enrich with OSV: a real GHSA severity label (deps.dev can't score a CVSS-4-only
      # advisory) and the fixed-version ranges the "capped below the fix" signal needs.
      # Native path is rubygems.
      OsvClient.enrich(vulnerabilities, ecosystem: :rubygems, name: gem_name)
      {
        scorecard_score: scorecard&.dig(:score),
        scorecard_maintained: scorecard&.dig(:maintained),
        vulnerability_count: vulnerabilities.length,
        vulnerabilities: vulnerabilities
      }
    end

    def versions(gem_name:, source_uri: nil)
      if github_packages_uri?(source_uri)
        fetch_github_packages_versions(gem_name: gem_name, source_uri: source_uri)
      elsif ArtifactoryClient.artifactory_uri?(source_uri)
        ArtifactoryClient.versions(gem_name: gem_name, source_uri: source_uri)
      elsif unqueryable_private_source?(source_uri)
        private_source_versions(gem_name: gem_name, source_uri: source_uri)
      else
        Gems.versions(gem_name)
      end
    rescue Gems::NotFound
      []
    # Gems::GemError is the `gems` library's catch-all for any non-success,
    # non-404 response -- crucially a 429 rate-limit or a 5xx. Left unrescued it
    # escapes to the per-gem rescue in #call and strips the gem of ALL its signals
    # (not just versions), blaming a generic "error occurred". The poison-pill
    # enrichment adds extra version lookups that make a 429 likelier, so a
    # best-effort feature must not be able to degrade an unrelated gem's core data:
    # degrade to "no versions known" here, exactly like Gems::NotFound.
    rescue Gems::GemError, *HttpHelper::TRANSPORT_ERRORS => e
      warn("warning: rubygems.org versions lookup failed for #{gem_name}: #{e.class} (#{e.message})")
      []
    end

    def github_packages_uri?(uri)
      uri.is_a?(String) && URI(uri).host == "rubygems.pkg.github.com"
    rescue URI::InvalidURIError
      false
    end

    # A rubygems-type source that isn't public rubygems.org and that we have no
    # client for (Gemfury, Gemstash, geminabox, a private mirror). We must NOT
    # fall through to Gems.versions, which always hits public rubygems.org: that
    # would silently report a public name-collision's data, or blanks, as if it
    # were the private gem's. github_packages/artifactory are handled above, so
    # anything left with a non-rubygems.org host is unqueryable. Refs #43.
    def unqueryable_private_source?(source_uri)
      return false unless source_uri.is_a?(String)

      # Hostnames are case-insensitive; a trailing dot (FQDN form) is equivalent.
      host = URI(source_uri).host&.downcase&.chomp(".")
      return false if host.nil?

      host != "rubygems.org" && !host.end_with?(".rubygems.org")
    rescue URI::InvalidURIError
      false
    end

    # Any Bundler-compatible private host (Contribsys, Gemstash, Gemfury, a private
    # mirror) serves the RubyGems compact index, since that is how `bundle install`
    # resolves from it. So try that agnostic rail before declaring the source
    # unqueryable: it covers the whole class with no per-host client, and falls
    # through to the same warning when a host does not serve it. Auth is Bundler's
    # own host-keyed credential only; still_active's ambient --artifactory-token is
    # never sent to a lockfile-derived host this way (that stays ArtifactoryClient's,
    # behind its host allowlist). The repo-signal path is untouched, so #43 still
    # blocks a public name-collision's repo data from standing in for the private gem.
    def private_source_versions(gem_name:, source_uri:)
      versions = CompactIndexClient.versions(
        gem_name: gem_name,
        source_uri: source_uri,
        headers: SourceCredentials.headers_for(source_uri)
      )
      return versions unless versions.empty?

      warn_unqueryable_private_source(gem_name: gem_name, source_uri: source_uri)
      []
    end

    def warn_unqueryable_private_source(gem_name:, source_uri:)
      host = URI(source_uri).host
      warn(
        "warning: #{gem_name} resolves from a private source (#{host}) still_active cannot query; " \
          "reporting no version/latest/libyear data for it rather than substituting public rubygems.org data"
      )
    end

    def fetch_github_packages_versions(gem_name:, source_uri:)
      base = URI(source_uri.chomp("/"))
      namespace_path = base.path
      path = "#{namespace_path}/api/v1/gems/#{CGI.escape(gem_name)}/versions.json"
      token = StillActive.config.github_oauth_token
      headers = token ? {"Authorization" => "Bearer #{token}"} : {}
      HttpHelper.get_json(base, path, headers: headers) || []
    end

    def repository_info_for_non_rubygems(gem_name:, source_uri: nil)
      valid_repository_url =
        [source_uri, *installed_gem_urls(gem_name: gem_name)].find { |url| Repository.valid?(url: url) }
      repo = Repository.url_with_owner_and_name(url: valid_repository_url)
      repo.merge(project_id: deps_dev_project_id(repo))
    end

    def repository_info_from_installed_gem(gem_name:)
      valid_repository_url =
        installed_gem_urls(gem_name: gem_name).find { |url| Repository.valid?(url: url) }
      repo = Repository.url_with_owner_and_name(url: valid_repository_url)
      repo.merge(project_id: deps_dev_project_id(repo))
    end

    # deps.dev scorecards index github.com and gitlab.com only. A Forgejo/Codeberg
    # repo has no deps.dev project, so leave its project_id nil rather than minting
    # a bogus github.com/owner/name that would fetch the wrong (or no) scorecard.
    DEPS_DEV_HOST_BY_SOURCE = {github: "github.com", gitlab: "gitlab.com"}.freeze

    def deps_dev_project_id(repo)
      host = DEPS_DEV_HOST_BY_SOURCE[repo[:source]]
      return unless repo[:url] && host

      "#{host}/#{repo[:owner]}/#{repo[:name]}"
    end

    def repository_info(gem_name:, versions:, source_uri: nil)
      valid_repository_url =
        installed_gem_urls(gem_name: gem_name).find { |url| Repository.valid?(url: url) } ||
        rubygems_versions_repository_url(versions: versions).find { |url| Repository.valid?(url: url) } ||
        public_rubygems_repository_url(gem_name: gem_name, source_uri: source_uri)
      Repository.url_with_owner_and_name(url: valid_repository_url)
    end

    # Locally-installed gem metadata and the gem's own version payload are
    # source-accurate. This public rubygems.org Gems.info lookup is the last
    # resort, and is skipped for an unqueryable private source: otherwise a
    # public name-collision's repo/archived/last-commit data would stand in for
    # the private gem, the same substitution #43 prevents for versions.
    def public_rubygems_repository_url(gem_name:, source_uri:)
      return if unqueryable_private_source?(source_uri)

      rubygems_gem_repository_url(gem_name: gem_name).find { |url| Repository.valid?(url: url) }
    end

    def installed_gem_urls(gem_name:)
      info = Gem::Dependency.new(gem_name).matching_specs.first
      return [] if info.nil?

      [
        info.metadata&.dig("source_code_uri"),
        info.homepage
      ].compact.uniq
    end

    def rubygems_versions_repository_url(versions:)
      versions
        .filter_map { |version| version.dig("metadata", "source_code_uri") }
        .uniq
    end

    def rubygems_gem_repository_url(gem_name:)
      info = Gems.info(gem_name)
      return [] if info.nil?

      [
        info["homepage_uri"],
        info["source_code_uri"]
      ].compact.uniq
    rescue Gems::NotFound
      []
    end

    # The repo-signal provider for a source, or nil for an unhandled host. Every
    # provider answers archived/last_commit_date; richer signals (e.g.
    # commits_since_release) are duck-typed and dispatched by respond_to?, so a
    # provider opts into them by defining the method, with no base class and no
    # assumption that every source supports every signal.
    def provider_for(source)
      case source
      # Without a GitHub token, the live API caps at 60 req/hr -- unusable past a
      # handful of gems. Fall back to ecosyste.ms (5000 anonymous) so a large
      # Gemfile still resolves. With a token, the live API stays primary (freshest,
      # and it carries commits_since_release, which ecosyste.ms doesn't).
      when :github then StillActive.config.github_oauth_token ? GithubClient : EcosystemsClient
      when :gitlab then GitlabClient
      when :forgejo then ForgejoClient
      end
    end

    # One provider call yields both archived and the last-activity date (the
    # repo object carries both), so a gem's repo signals cost a single request
    # instead of two. Returns {} for an unhandled host.
    def repo_signals(source:, repository_owner:, repository_name:)
      provider_for(source)&.repo_signals(owner: repository_owner, name: repository_name) || {}
    end

    def unreleased_commits(source:, repository_owner:, repository_name:, version:)
      provider = provider_for(source)
      return unless provider.respond_to?(:commits_since_release)

      provider.commits_since_release(owner: repository_owner, name: repository_name, version: version)
    end
  end
end
