# frozen_string_literal: true

require_relative "deps_dev_client"
require_relative "gitlab_client"
require_relative "repository"
require_relative "../helpers/health_score_helper"
require_relative "../helpers/libyear_helper"
require_relative "../helpers/ruby_helper"
require_relative "../helpers/version_helper"
require "async"
require "async/barrier"
require "async/semaphore"
require "gems"

module StillActive
  module Workflow
    extend self

    def call(&on_progress)
      task = Async do
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
        result_object
      end
      task.wait
    end

    def ruby_freshness
      RubyHelper.ruby_freshness
    end

    private

    def gem_info(gem_name:, result_object:, gem_version: nil, source_type: :rubygems, source_uri: nil)
      result_object[gem_name] = { source_type: source_type }
      result_object[gem_name][:version_used] = gem_version if gem_version

      case source_type
      when :path
        gem_info_path(gem_name: gem_name, result_object: result_object)
      when :git
        gem_info_git(gem_name: gem_name, result_object: result_object)
      else
        gem_info_rubygems(
          gem_name: gem_name,
          gem_version: gem_version,
          result_object: result_object,
          source_uri: source_uri,
        )
      end

      result_object[gem_name][:health_score] = HealthScoreHelper.gem_score(result_object[gem_name])
    end

    def gem_info_rubygems(gem_name:, gem_version:, result_object:, source_uri:)
      vs = versions(gem_name: gem_name, source_uri: source_uri)
      repo_info = repository_info(gem_name: gem_name, versions: vs)
      commit_date = last_commit_date(
        source: repo_info[:source],
        repository_owner: repo_info[:owner],
        repository_name: repo_info[:name],
      )
      archived = repo_archived?(
        source: repo_info[:source],
        repository_owner: repo_info[:owner],
        repository_name: repo_info[:name],
      )
      last_release = VersionHelper.find_version(versions: vs, pre_release: false)
      last_pre_release = VersionHelper.find_version(versions: vs, pre_release: true)
      deps_dev = fetch_deps_dev_info(
        gem_name: gem_name,
        version: gem_version || VersionHelper.gem_version(version_hash: last_release),
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
          libyear: LibyearHelper.gem_libyear(
            version_used_release_date: VersionHelper.release_date(version_hash: version_used),
            latest_version_release_date: VersionHelper.release_date(version_hash: last_release),
          ),
        })
      end
    end

    def gem_info_git(gem_name:, result_object:)
      repo_info = repository_info_from_installed_gem(gem_name: gem_name)
      source, owner, name = repo_info.values_at(:source, :owner, :name)

      result_object[gem_name].merge!({
        repository_url: repo_info[:url],
        last_commit_date: last_commit_date(source:, repository_owner: owner, repository_name: name),
        archived: repo_archived?(source:, repository_owner: owner, repository_name: name),
        scorecard_score: DepsDevClient.project_scorecard(project_id: repo_info[:project_id])&.dig(:score),
      })
    end

    def gem_info_path(gem_name:, result_object:)
      repo_info = repository_info_from_installed_gem(gem_name: gem_name)
      source, owner, name = repo_info.values_at(:source, :owner, :name)

      result_object[gem_name].merge!({
        repository_url: repo_info[:url],
        last_commit_date: last_commit_date(source:, repository_owner: owner, repository_name: name),
        archived: repo_archived?(source:, repository_owner: owner, repository_name: name),
        scorecard_score: DepsDevClient.project_scorecard(project_id: repo_info[:project_id])&.dig(:score),
      })
    end

    def fetch_deps_dev_info(gem_name:, version:)
      info = DepsDevClient.version_info(gem_name: gem_name, version: version)
      scorecard = DepsDevClient.project_scorecard(project_id: info&.dig(:project_id))
      advisory_keys = info&.dig(:advisory_keys) || []
      vulnerabilities = advisory_keys.filter_map { |id| DepsDevClient.advisory_detail(advisory_id: id) }
      {
        scorecard_score: scorecard&.dig(:score),
        vulnerability_count: advisory_keys.length,
        vulnerabilities: vulnerabilities,
      }
    end

    def versions(gem_name:, source_uri: nil)
      if github_packages_uri?(source_uri)
        fetch_github_packages_versions(gem_name: gem_name, source_uri: source_uri)
      else
        Gems.versions(gem_name)
      end
    rescue Gems::NotFound
      []
    end

    def github_packages_uri?(uri)
      uri.is_a?(String) && uri.include?("rubygems.pkg.github.com")
    end

    def fetch_github_packages_versions(gem_name:, source_uri:)
      base = URI(source_uri.chomp("/"))
      namespace_path = base.path
      path = "#{namespace_path}/api/v1/gems/#{gem_name}/versions.json"
      token = StillActive.config.github_oauth_token
      headers = token ? { "Authorization" => "Bearer #{token}" } : {}
      HttpHelper.get_json(base, path, headers: headers) || []
    end

    def repository_info_from_installed_gem(gem_name:)
      valid_repository_url =
        installed_gem_urls(gem_name: gem_name).find { |url| Repository.valid?(url: url) }
      repo = Repository.url_with_owner_and_name(url: valid_repository_url)
      project_id = if repo[:url]
        host = repo[:source] == :gitlab ? "gitlab.com" : "github.com"
        "#{host}/#{repo[:owner]}/#{repo[:name]}"
      end
      repo.merge(project_id: project_id)
    end

    def repository_info(gem_name:, versions:)
      valid_repository_url =
        installed_gem_urls(gem_name: gem_name).find { |url| Repository.valid?(url: url) } ||
        rubygems_versions_repository_url(versions: versions).find { |url| Repository.valid?(url: url) } ||
        rubygems_gem_repository_url(gem_name: gem_name).find { |url| Repository.valid?(url: url) }
      Repository.url_with_owner_and_name(url: valid_repository_url)
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

    def repo_archived?(source:, repository_owner:, repository_name:)
      case source
      when :github
        repo = StillActive.config.github_client.repository("#{repository_owner}/#{repository_name}")
        repo&.archived
      when :gitlab
        GitlabClient.archived?(owner: repository_owner, name: repository_name)
      end
    rescue StandardError
      nil
    end

    def last_commit_date(source:, repository_owner:, repository_name:)
      case source
      when :github
        commit = StillActive.config.github_client.commits("#{repository_owner}/#{repository_name}", per_page: 1)&.first
        date = commit&.commit&.author&.date
        case date
        when Time then date
        when String then Time.parse(date)
        end
      when :gitlab
        GitlabClient.last_commit_date(owner: repository_owner, name: repository_name)
      end
    end
  end
end
