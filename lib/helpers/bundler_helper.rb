# frozen_string_literal: true

require_relative "lockfile_dependency_parser"

module StillActive
  module BundlerHelper
    extend self

    def gemfile_dependencies(gemfile_path: StillActive.config.gemfile_path)
      absolute_gemfile = File.expand_path(gemfile_path)
      lockfile = lockfile_path_for(absolute_gemfile)
      unless File.file?(lockfile)
        raise MissingLockfileError,
          "no lockfile next to #{absolute_gemfile}; run `bundle lock` (or `bundle install`) first"
      end

      parsed = LockfileDependencyParser.parse(File.read(lockfile))
      if parsed[:plugin_source?]
        warn("warning: lockfile contains a PLUGIN SOURCE block; still_active does not audit Bundler plugins, skipping it")
      end

      direct = parsed[:direct]
      parsed[:specs]
        .select { |spec| direct.include?(spec.name) }
        .uniq(&:name)
        .map do |spec|
          {
            name: spec.name,
            version: spec.version,
            source_type: spec.source_type || :unknown,
            source_uri: spec.source_uri,
          }
        end
    end

    # Bundler's lockfile naming: `gems.rb` pairs with `gems.locked`, every other
    # Gemfile with `<gemfile>.lock`. Derived from the explicit path rather than
    # global Bundler state so `--gemfile` is honoured even under `bundle exec`
    # (where a memoized Bundler.definition / ambient BUNDLE_GEMFILE would
    # otherwise win). Refs #42.
    def lockfile_path_for(gemfile)
      if File.basename(gemfile) == "gems.rb"
        File.join(File.dirname(gemfile), "gems.locked")
      else
        "#{gemfile}.lock"
      end
    end
  end
end
