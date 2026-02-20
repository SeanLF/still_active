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
        .map do |spec|
          {
            name: spec.name,
            version: spec.version.version,
            source_type: detect_source_type(spec),
            source_uri: detect_source_uri(spec),
          }
        end
    end

    private

    def detect_source_type(spec)
      case spec.source
      when ::Bundler::Source::Rubygems then :rubygems
      when ::Bundler::Source::Git then :git
      when ::Bundler::Source::Path then :path
      else :unknown
      end
    end

    def detect_source_uri(spec)
      case spec.source
      when ::Bundler::Source::Rubygems
        spec.source.remotes&.first&.to_s
      when ::Bundler::Source::Git
        spec.source.uri
      when ::Bundler::Source::Path
        spec.source.path&.to_s
      end
    end
  end
end
