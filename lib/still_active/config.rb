# frozen_string_literal: true

require "bundler"
require "octokit"

module StillActive
  class Config
    attr_accessor :critical_warning_emoji,
      :fail_if_critical,
      :fail_if_warning,
      :futurist_emoji,
      :gemfile_path,
      :gems,
      :github_oauth_token,
      :gitlab_token,
      :fail_if_outdated,
      :fail_if_vulnerable,
      :ignored_gems,
      :output_format,
      :parallelism,
      :no_warning_range_end,
      :success_emoji,
      :unsure_emoji,
      :warning_emoji,
      :warning_range_end

    def initialize
      @fail_if_critical = false
      @fail_if_outdated = nil
      @fail_if_vulnerable = nil
      @fail_if_warning = false
      @gemfile_path = Bundler.default_gemfile.to_s
      @gems = []
      @ignored_gems = []
      @github_oauth_token = ENV["GITHUB_TOKEN"]
      @gitlab_token = ENV["GITLAB_TOKEN"]

      @parallelism = 10

      @output_format = :auto

      @critical_warning_emoji = "🚩"
      @futurist_emoji = "🔮"
      @success_emoji = "✅"
      @unsure_emoji = "❓"
      @warning_emoji = "⚠️"

      @no_warning_range_end = 1
      @warning_range_end = 3
    end

    def github_client
      @github_client ||=
        Octokit::Client.new(access_token: github_oauth_token)
    end
  end
end
