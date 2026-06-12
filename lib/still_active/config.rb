# frozen_string_literal: true

require "bundler"
require "octokit"
require "open3"

module StillActive
  class Config
    attr_writer :github_oauth_token, :gitlab_token, :forgejo_token, :artifactory_token, :artifactory_host, :gemfile_path
    attr_accessor :alternatives,
      :baseline_path,
      :critical_warning_emoji,
      :cyclonedx_path,
      :cyclonedx_version,
      :fail_if_critical,
      :fail_if_warning,
      :futurist_emoji,
      :gems,
      :fail_if_outdated,
      :fail_if_vulnerable,
      :ignored_gems,
      :output_format,
      :parallelism,
      :no_warning_range_end,
      :sarif_path,
      :success_emoji,
      :unsure_emoji,
      :warning_emoji,
      :warning_range_end

    def initialize
      @alternatives = false
      @fail_if_critical = false
      @fail_if_outdated = nil
      @fail_if_vulnerable = nil
      @fail_if_warning = false
      @gemfile_path = nil
      @gems = []
      @ignored_gems = []
      @github_oauth_token = nil
      @gitlab_token = nil
      @forgejo_token = nil
      @artifactory_token = nil
      @artifactory_host = nil

      @parallelism = 10

      @output_format = :auto
      @sarif_path = nil
      @baseline_path = nil
      @cyclonedx_path = nil
      @cyclonedx_version = "1.6"

      @critical_warning_emoji = "🚩"
      @futurist_emoji = "🔮"
      @success_emoji = "✅"
      @unsure_emoji = "❓"
      @warning_emoji = "⚠️"

      # Release-age thresholds (years) calibrated against real RubyGems cadence,
      # not the npm-derived 12-month convention: healthy mature gems routinely go
      # 12-18 months between releases, so the ok ceiling is 18 months. > 3 years
      # is critical. See #32.
      @no_warning_range_end = 1.5
      @warning_range_end = 3
    end

    def github_client
      @github_client ||=
        Octokit::Client.new(access_token: github_oauth_token)
    end

    def github_oauth_token
      @github_oauth_token ||= presence(ENV["GITHUB_TOKEN"]) || presence(ENV["GH_TOKEN"]) || gh_cli_token
    end

    def gitlab_token
      @gitlab_token ||= presence(ENV["GITLAB_TOKEN"]) || glab_cli_token
    end

    # Codeberg/Forgejo has no ubiquitous CLI to borrow a token from (unlike
    # gh/glab), so it's env-var only. Anonymous works for public repos; a token
    # only raises the rate limit. CODEBERG_TOKEN is accepted as a convenience
    # alias for the codeberg.org default host.
    def forgejo_token
      @forgejo_token ||= presence(ENV["STILL_ACTIVE_FORGEJO_TOKEN"]) || presence(ENV["CODEBERG_TOKEN"])
    end

    def artifactory_token
      @artifactory_token ||= presence(ENV["STILL_ACTIVE_ARTIFACTORY_TOKEN"])
    end

    def artifactory_host
      @artifactory_host ||= presence(ENV["STILL_ACTIVE_ARTIFACTORY_HOST"])
    end

    # Lazy so that running with --gems=... (no Gemfile needed) doesn't crash
    # when invoked from a directory without a Gemfile in the tree.
    def gemfile_path
      @gemfile_path ||= begin
        Bundler.default_gemfile.to_s
      rescue Bundler::GemfileNotFound
        File.join(Dir.pwd, "Gemfile")
      end
    end

    private

    def gh_cli_token
      stdout, stderr, status = Open3.capture3("gh", "auth", "token")
      if status.success?
        token = presence(stdout.strip)
        return token if token

        warn("warning: `gh auth token` returned empty output")
      else
        warn("warning: `gh auth token` failed: #{stderr.strip}")
      end
      nil
    rescue Errno::ENOENT
      nil
    end

    def glab_cli_token
      # Scope to gitlab.com to match GitlabClient::BASE_URI. Users on self-hosted
      # GitLab still_active doesn't query anyway; if they need it, set GITLAB_TOKEN.
      _stdout, stderr, status = Open3.capture3("glab", "auth", "status", "--hostname=gitlab.com", "--show-token")
      unless status.success?
        warn("warning: `glab auth status` failed: #{stderr.strip}")
        return
      end

      match = stderr.match(/Token:\s*(\S+)/)
      return match[1] if match

      warn("warning: `glab auth status` did not return a Token line")
      nil
    rescue Errno::ENOENT
      nil
    end

    def presence(value)
      value && !value.empty? ? value : nil
    end
  end
end
