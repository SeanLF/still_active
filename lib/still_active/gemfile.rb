# frozen_string_literal: true

require "bundler"

module StillActive
  module Gemfile
    extend self

    def dependencies(gemfile_path:)
      Bundler::SharedHelpers.set_env("BUNDLE_GEMFILE", File.expand_path(gemfile_path))
      Bundler.definition.dependencies.map(&:name)
    end
  end
end
