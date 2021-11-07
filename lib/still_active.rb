# frozen_string_literal: true

require_relative "still_active/version"
require_relative "still_active/config"
require_relative "still_active/cli"

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
