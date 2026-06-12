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

    # Commits on the default branch since the latest release's tag: the
    # "unreleased work" signal. GitHub's compare endpoint returns ahead_by as a
    # single scalar, so this is one cheap call. The git tag name isn't carried
    # by RubyGems, so resolve it from the version by trying the two ubiquitous
    # forms (v7.0.1, 7.0.1) as the compare base; a wrong form 404s and we try
    # the next. Returns nil when neither resolves (non-tagging repo, monorepo
    # tag scheme we don't guess). Only GithubClient implements this; the
    # workflow dispatches by respond_to?, so GitLab/Forgejo simply don't.
    def commits_since_release(owner:, name:, version:)
      return if owner.nil? || name.nil? || version.nil?

      repo = "#{owner}/#{name}"
      ["v#{version}", version.to_s].each do |tag|
        return StillActive.config.github_client.compare(repo, tag, "HEAD").ahead_by
      rescue Octokit::NotFound
        # this tag form doesn't exist; fall through to try the next one
      end
      nil
    rescue Octokit::Error, Faraday::Error => e
      $stderr.puts("warning: unreleased-commits check failed for #{owner}/#{name}: #{e.class}")
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
