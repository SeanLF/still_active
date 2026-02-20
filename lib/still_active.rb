# frozen_string_literal: true

require_relative "still_active/version"
require_relative "still_active/config"
require_relative "still_active/cli"

# Octokit depends on Faraday and emits a deprecation warning at load time
# unless faraday-retry is available. Requiring it here silences that warning.
require "faraday/retry"

module StillActive
  class Error < StandardError; end

  class << self
    def config
      @config ||= Config.new
      if block_given?
        yield @config
      else
        @config
      end
    end

    def reset
      @config = Config.new
    end
  end
end
