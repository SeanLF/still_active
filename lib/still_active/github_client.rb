# frozen_string_literal: true

require "time"
require "octokit"

module StillActive
  # Repo signals (archived?, last commit date) for github.com-hosted gems.
  # Wraps Octokit so the rest of the workflow dispatches to a provider with the
  # same shape as GitlabClient, rather than reaching into Octokit inline. The
  # Octokit dependency stays internal to this module.
  module GithubClient
    extend self

    def archived(owner:, name:)
      return if owner.nil? || name.nil?

      StillActive.config.github_client.repository("#{owner}/#{name}")&.archived
    rescue Octokit::Error, Faraday::Error => e
      $stderr.puts("warning: archived check failed for #{owner}/#{name}: #{e.class}")
      nil
    end

    def last_commit_date(owner:, name:)
      return if owner.nil? || name.nil?

      commit = StillActive.config.github_client.commits("#{owner}/#{name}", per_page: 1)&.first
      date = commit&.commit&.author&.date
      case date
      when Time then date
      when String then parse_commit_date(date, owner, name)
      end
    rescue Octokit::Error, Faraday::Error => e
      $stderr.puts("warning: last commit check failed for #{owner}/#{name}: #{e.class}")
      nil
    end

    private

    def parse_commit_date(date, owner, name)
      Time.parse(date)
    rescue ArgumentError
      $stderr.puts("warning: could not parse commit date for #{owner}/#{name}: #{date.inspect}")
      nil
    end
  end
end
