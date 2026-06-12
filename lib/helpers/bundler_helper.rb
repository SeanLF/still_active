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

      audited = audited_names(parsed)
      parsed[:specs]
        .select { |spec| audited.include?(spec.name) }
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

    # The DEPENDENCIES names, plus the runtime deps of any local path-sourced gem
    # reachable from them (a gemspec project's own gem, or a local Rails engine).
    # A `gemspec` / `gem path:` directive surfaces the local gem's *development*
    # deps in DEPENDENCIES but its *runtime* deps arrive only as that gem's
    # nested lockfile deps, so without this a gem maintainer auditing their own
    # repo would never see the deps they ship. We follow path gems transitively
    # (nested engines) but never expand a regular gem's transitive graph, keeping
    # parity with the "audit what you declare" scope for normal projects. Refs #41.
    def audited_names(parsed)
      specs_by_name = parsed[:specs].to_h { |spec| [spec.name, spec] }
      names = []
      queue = parsed[:direct].dup

      until queue.empty?
        name = queue.shift
        next if names.include?(name)

        names << name
        spec = specs_by_name[name]
        queue.concat(spec.dependencies) if spec&.source_type == :path
      end

      names
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
