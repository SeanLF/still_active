# frozen_string_literal: true

require "bundler"

module StillActive
  class Config
    attr_accessor :critical_warning_emoji, :futurist_emoji, :gemfile_path, :gems, :github_oauth_token, :output_format,
      :safe_range_end, :safe_range_start, :success_emoji, :unsure_emoji, :warning_emoji, :warning_range_end,
      :warning_range_start

    def initialize
      @gemfile_path = Bundler.default_gemfile.to_s
      @gems = []

      @output_format = :markdown

      @critical_warning_emoji = "🚩"
      @futurist_emoji = "🔮"
      @success_emoji = "✅"
      @unsure_emoji = "❓"
      @warning_emoji = "⚠️"

      @safe_range_start = 0
      @safe_range_end = 1

      @warning_range_start = 2
      @warning_range_end = 3
    end

    def github_client
      @github_client ||=
        Github.new(oauth_token: github_oauth_token)
    end
  end
end
