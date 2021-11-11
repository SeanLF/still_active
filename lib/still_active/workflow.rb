# frozen_string_literal: true

require_relative "repository"
require_relative "../helpers/version_helper"
require "async"
require "async/barrier"
require "async/semaphore"
require "gems"
require "github_api"

module StillActive
  module Workflow
    extend self
    include VersionHelper

    def call
      task = Async do
        barrier = Async::Barrier.new
        semaphore = Async::Semaphore.new(StillActive.config.simultaneous_request_quantity, parent: barrier)
        result_object = {}
        StillActive.config.gems.each_with_object(result_object) do |gem, hash|
          semaphore.async do
            gem_info(gem_name: gem[:name], result_object: hash, gem_version: gem.dig(:version))
          end
        end
        barrier.wait
        result_object
      end
      task.wait
    end

    private

    def gem_info(gem_name:, result_object:, gem_version: nil)
      result_object[gem_name] = {}
      result_object[gem_name].merge!({
        version_used: gem_version,
      }) if gem_version

      vs = versions(gem_name: gem_name)
      repo_info = repository_info(gem_name: gem_name, versions: vs)
      last_commit_date = last_commit_date(source: repo_info[:source], repository_owner: repo_info[:owner],
        repository_name: repo_info[:name])
      last_release = find_version(versions: vs, pre_release: false)
      last_pre_release = find_version(versions: vs, pre_release: true)
      result_object[gem_name].merge!({
        latest_version: gem_version(version_hash: last_release),
        latest_version_release_date: release_date(version_hash: last_release),

        latest_pre_release_version: gem_version(version_hash: last_pre_release),
        latest_pre_release_version_release_date: release_date(version_hash: last_pre_release),

        repository_url: repo_info[:url],
        last_commit_date: last_commit_date,
      })

      unless vs.empty?
        result_object[gem_name].merge!({ ruby_gems_url: "https://rubygems.org/gems/#{gem_name}" })
      end

      if gem_version
        version_used = find_version(versions: vs, version_string: gem_version)
        result_object[gem_name].merge!({
          # global_warning: global_warning,
          up_to_date:
            up_to_date?(
              version_used: version_used,
              latest_version: last_release,
              latest_pre_release_version: last_pre_release
            ),

          version_used_release_date: release_date(version_hash: version_used),
        })
      end
    rescue StandardError => e
      puts "error occured for #{gem_name}: #{e.class}\n\t#{e.message}"
    end

    # makes network request
    def versions(gem_name:)
      Gems.versions(gem_name)
    rescue Gems::NotFound
      []
    end

    def repository_info(gem_name:, versions:)
      # binding.break # if gem_name == "still_active"
      valid_repository_url =
        installed_gem_urls(gem_name: gem_name).find { |url| Repository.valid?(url: url) } ||
        rubygems_versions_repository_url(versions: versions).find { |url| Repository.valid?(url: url) } ||
        rubygems_gem_repository_url(gem_name: gem_name).find { |url| Repository.valid?(url: url) }
      Repository.url_with_owner_and_name(url: valid_repository_url)
    end

    # does not make network requests
    def installed_gem_urls(gem_name:)
      info = Gem::Dependency.new(gem_name).matching_specs.first
      return [] if info.nil?

      [
        info&.metadata&.dig("source_code_uri"),
        info&.homepage,
      ].compact.uniq
    end

    # does not make network requests
    def rubygems_versions_repository_url(versions:)
      versions
        .map { |version| version.dig("metadata", "source_code_uri") }
        .compact
        .uniq
    end

    # makes network request
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

    # makes network request
    def last_commit(source:, repository_owner:, repository_name:)
      case source.to_sym
      when :github
        StillActive.config.github_client.repos.commits.all(repository_owner, repository_name, per_page: 1)&.first
        # when :gitlab
        #   Gitlab.commits(name, per_page: 1)
      end
    end

    # makes network request
    def last_commit_date(source:, repository_owner:, repository_name:)
      commit = last_commit(source: source, repository_owner: repository_owner, repository_name: repository_name)
      case source.to_sym
      when :github
        commit&.dig("commit", "author", "date").then { |date| Time.parse(date) unless date.nil? }
        # when :gitlab
        #   commit
      end
    end
  end
end
