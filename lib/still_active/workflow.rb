# frozen_string_literal: true

require_relative "artifactory_client"
require_relative "deps_dev_client"
require_relative "forgejo_client"
require_relative "github_client"
require_relative "gitlab_client"
require_relative "repository"
require_relative "../helpers/activity_helper"
require_relative "../helpers/alternatives_helper"
require_relative "../helpers/catalog_index"
require_relative "../helpers/libyear_helper"
require_relative "../helpers/ruby_advisory_db"
require_relative "../helpers/ruby_helper"
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
        barrier = Async::Barrier.new
        semaphore = Async::Semaphore.new(StillActive.config.parallelism, parent: barrier)
        result_object = {}
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
            )
          rescue Octokit::TooManyRequests
            $stderr.print("\r\e[K") if on_progress
            $stderr.puts("rate limited checking #{gem[:name]}: set GITHUB_TOKEN to increase your limit")
          rescue StandardError => e
            $stderr.print("\r\e[K") if on_progress
            $stderr.puts("error occurred for #{gem[:name]}: #{e.class}\n\t#{e.message}")
          ensure
            completed += 1
            on_progress&.call(completed, total)
          end
        end
        barrier.wait
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

    def gem_info(gem_name:, result_object:, gem_version: nil, source_type: :rubygems, source_uri: nil, direct: true, dependency_path: nil, advisory_db: nil, catalog: nil)
      result_object[gem_name] = { source_type: source_type, direct: direct }
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
        )
      end

      attach_alternatives(gem_name: gem_name, result_object: result_object, catalog: catalog)
    end

    def gem_info_rubygems(gem_name:, gem_version:, result_object:, source_uri:, advisory_db: nil)
      vs = versions(gem_name: gem_name, source_uri: source_uri)
      repo_info = repository_info(gem_name: gem_name, versions: vs, source_uri: source_uri)
      signals = repo_signals(
        source: repo_info[:source],
        repository_owner: repo_info[:owner],
        repository_name: repo_info[:name],
      )
      commit_date = signals[:last_commit_date]
      archived = signals[:archived]
      last_release = VersionHelper.find_version(versions: vs, pre_release: false)
      last_pre_release = VersionHelper.find_version(versions: vs, pre_release: true)
      deps_dev = fetch_deps_dev_info(
        gem_name: gem_name,
        version: gem_version || VersionHelper.gem_version(version_hash: last_release),
        advisory_db: advisory_db,
      )
      result_object[gem_name].merge!({
        latest_version: VersionHelper.gem_version(version_hash: last_release),
        latest_version_release_date: VersionHelper.release_date(version_hash: last_release),

        latest_pre_release_version: VersionHelper.gem_version(version_hash: last_pre_release),
        latest_pre_release_version_release_date: VersionHelper.release_date(version_hash: last_pre_release),

        repository_url: repo_info[:url],
        last_commit_date: commit_date,
        archived: archived,
        **deps_dev,
      })

      unless vs.empty?
        result_object[gem_name][:ruby_gems_url] = "https://rubygems.org/gems/#{gem_name}"
      end

      if StillActive.config.unreleased_commits
        result_object[gem_name][:unreleased_commits] = unreleased_commits(
          source: repo_info[:source],
          repository_owner: repo_info[:owner],
          repository_name: repo_info[:name],
          version: VersionHelper.gem_version(version_hash: last_release),
        )
      end

      if gem_version
        version_used = VersionHelper.find_version(versions: vs, version_string: gem_version)
        result_object[gem_name].merge!({
          up_to_date: VersionHelper.up_to_date(
            version_used: version_used,
            latest_version: last_release,
            latest_pre_release_version: last_pre_release,
          ),

          version_used_release_date: VersionHelper.release_date(version_hash: version_used),
          version_yanked: !vs.empty? && version_used.nil?,
          license: VersionHelper.license(version_hash: version_used),
          libyear: LibyearHelper.gem_libyear(
            version_used_release_date: VersionHelper.release_date(version_hash: version_used),
            latest_version_release_date: VersionHelper.release_date(version_hash: last_release),
          ),
        })
      end
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
        **deps_dev,
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
    rescue StandardError
      nil # cosmetic best-effort: lead-fetching must never break the core audit
    end

    def fetch_deps_dev_info(gem_name:, version:, advisory_db: nil)
      info = DepsDevClient.version_info(gem_name: gem_name, version: version)
      scorecard = DepsDevClient.project_scorecard(project_id: info&.dig(:project_id))
      advisory_keys = info&.dig(:advisory_keys) || []
      deps_dev_vulns = advisory_keys.filter_map { |id| DepsDevClient.advisory_detail(advisory_id: id) }
      radb_vulns = RubyAdvisoryDb.advisories_for(database: advisory_db, gem_name: gem_name, version: version)
      vulnerabilities = VulnerabilityHelper.merge_advisories(deps_dev: deps_dev_vulns, ruby_advisory_db: radb_vulns)
      {
        scorecard_score: scorecard&.dig(:score),
        scorecard_maintained: scorecard&.dig(:maintained),
        vulnerability_count: vulnerabilities.length,
        vulnerabilities: vulnerabilities,
      }
    end

    def versions(gem_name:, source_uri: nil)
      if github_packages_uri?(source_uri)
        fetch_github_packages_versions(gem_name: gem_name, source_uri: source_uri)
      elsif ArtifactoryClient.artifactory_uri?(source_uri)
        ArtifactoryClient.versions(gem_name: gem_name, source_uri: source_uri)
      elsif unqueryable_private_source?(source_uri)
        warn_unqueryable_private_source(gem_name: gem_name, source_uri: source_uri)
        []
      else
        Gems.versions(gem_name)
      end
    rescue Gems::NotFound
      []
    rescue Errno::ECONNRESET, Errno::ECONNREFUSED, Net::OpenTimeout, Net::ReadTimeout, SocketError => e
      $stderr.puts("warning: rubygems.org versions lookup failed for #{gem_name}: #{e.class} (#{e.message})")
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

    def warn_unqueryable_private_source(gem_name:, source_uri:)
      host = URI(source_uri).host
      $stderr.puts(
        "warning: #{gem_name} resolves from a private source (#{host}) still_active cannot query; " \
          "reporting no version/latest/libyear data for it rather than substituting public rubygems.org data",
      )
    end

    def fetch_github_packages_versions(gem_name:, source_uri:)
      base = URI(source_uri.chomp("/"))
      namespace_path = base.path
      path = "#{namespace_path}/api/v1/gems/#{CGI.escape(gem_name)}/versions.json"
      token = StillActive.config.github_oauth_token
      headers = token ? { "Authorization" => "Bearer #{token}" } : {}
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
    DEPS_DEV_HOST_BY_SOURCE = { github: "github.com", gitlab: "gitlab.com" }.freeze

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
        info.homepage,
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
        info["source_code_uri"],
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
      when :github then GithubClient
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
