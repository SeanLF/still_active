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

    # A rate-limit response whose reset is at most this many seconds away is
    # waited out and retried; a longer wait (hourly-limit exhaustion) is not
    # auto-taken and falls through to the caller's rescue (warn + nil).
    MAX_RATE_LIMIT_WAIT = 60

    # archived + last-activity date from a single repository call. The repo
    # object's pushed_at (last push) stands in for the last-commit date: it
    # matches the default-branch commit date to the day in practice, and folding
    # the two signals into one call halves the per-gem GitHub requests. Returns
    # {} when the repo can't be read, so the caller leaves both signals blank.
    def repo_signals(owner:, name:)
      return {} if owner.nil? || name.nil?

      repo = with_rate_limit_retry("repo #{owner}/#{name}") do
        StillActive.config.github_client.repository("#{owner}/#{name}")
      end
      return {} unless repo

      {archived: repo.archived, last_commit_date: as_time(repo.pushed_at, owner, name)}
    rescue Octokit::Error, Faraday::Error => e
      warn("warning: repo signals failed for #{owner}/#{name}: #{e.class}")
      {}
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
        return with_rate_limit_retry("unreleased-commits #{repo}") { StillActive.config.github_client.compare(repo, tag, "HEAD").ahead_by }
      rescue Octokit::NotFound
        # this tag form doesn't exist; fall through to try the next one
      end
      nil
    rescue Octokit::Error, Faraday::Error => e
      warn("warning: unreleased-commits check failed for #{owner}/#{name}: #{e.class}")
      nil
    end

    private

    # Pause-and-retry on a rate-limit response when the reset is near, so a
    # transient secondary/burst limit (which GitHub's concurrent fan-out can
    # trip even with a token) self-heals instead of dropping the gem's signal.
    # Retries at most once. Under the async reactor, sleep yields to other
    # fibers rather than blocking the thread.
    def with_rate_limit_retry(label)
      retried = false
      begin
        yield
      rescue Octokit::TooManyRequests => e
        wait = rate_limit_wait(e)
        if retried || wait.nil? || wait > MAX_RATE_LIMIT_WAIT
          # Hourly-limit exhaustion (or a far reset): not worth auto-waiting.
          # Surface the one actionable hint rather than a generic class name,
          # then return nil so this signal is simply absent for the gem.
          warn("rate limited on #{label}; set GITHUB_TOKEN to raise your limit, or run less often")
          return
        end

        retried = true
        warn("rate limited on #{label}; waiting #{wait}s for reset")
        sleep(wait)
        retry
      end
    end

    # Seconds to wait before retrying, from the Retry-After header (secondary
    # limits) or x-ratelimit-reset (primary), or nil when neither is present.
    def rate_limit_wait(error)
      # Octokit normalises response headers to lowercase (Faraday is
      # case-insensitive), so a single lowercase lookup covers any casing.
      headers = response_headers(error)
      return if headers.nil? || headers.empty?

      if (retry_after = headers["retry-after"])
        return retry_after.to_i
      end

      reset = headers["x-ratelimit-reset"]
      return if reset.nil?

      [reset.to_i - Time.now.to_i, 0].max
    end

    # Octokit raises NoMethodError reading headers off an error with no response
    # attached; treat only that as "can't tell" so the limiter degrades to no
    # wait, while a real NoMethodError elsewhere still surfaces.
    def response_headers(error)
      error.response_headers
    rescue NoMethodError
      nil
    end

    def as_time(value, owner, name)
      return value if value.is_a?(Time)
      return if value.nil?

      Time.parse(value)
    rescue ArgumentError
      warn("warning: could not parse repo date for #{owner}/#{name}: #{value.inspect}")
      nil
    end
  end
end
