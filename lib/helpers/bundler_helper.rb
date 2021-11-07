# frozen_string_literal: true

module StillActive
  module BundlerHelper
    extend self

    def gemfile_dependencies(gemfile_path: StillActive.config.gemfile_path)
      ::Bundler::SharedHelpers.set_env("BUNDLE_GEMFILE", File.expand_path(gemfile_path))
      gemfile_gems = ::Bundler.definition.dependencies.map(&:name)
      Bundler
        .definition
        .locked_gems
        .specs
        .select { |spec| gemfile_gems.include?(spec.name) }
        .each_with_object([]) { |spec, array| array << { name: spec.name, version: spec.version.version } }
    end
  end
end
