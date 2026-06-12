# frozen_string_literal: true

require "set"
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

      direct = audited_names(parsed)
      # Maintenance signals cover the full resolved graph by default (matching
      # libyear-bundler and the CVE scanners we compose with); --direct-only
      # opts back to just the declared/shipped set. Transitive gems carry the
      # path back to the direct dep that pulls them in, so an un-actionable
      # transitive flag becomes an actionable "replace your direct gem A". #60.
      audited = StillActive.config.direct_only ? direct : parsed[:specs].map(&:name)
      direct_set = direct.to_set
      paths = StillActive.config.direct_only ? {} : dependency_paths(parsed[:specs], direct)

      parsed[:specs]
        .select { |spec| audited.include?(spec.name) }
        .uniq(&:name)
        .map do |spec|
          is_direct = direct_set.include?(spec.name)
          {
            name: spec.name,
            version: spec.version,
            source_type: spec.source_type || :unknown,
            source_uri: spec.source_uri,
            direct: is_direct,
            dependency_path: is_direct ? nil : paths[spec.name],
          }
        end
    end

    # Shortest path from a direct dependency to each reachable gem, by BFS over
    # the lockfile's resolved dependency edges. A direct root maps to [name];
    # a transitive gem maps to [direct_root, ..., name], whose head names the
    # direct dependency a maintainer can actually act on. An unreachable spec
    # (no declared ancestor) gets no path.
    def dependency_paths(specs, roots)
      specs_by_name = specs.to_h { |spec| [spec.name, spec] }
      paths = {}
      queue = []
      roots.each do |name|
        paths[name] = [name]
        queue << name
      end

      until queue.empty?
        name = queue.shift
        specs_by_name[name]&.dependencies&.each do |dep|
          next if paths.key?(dep)

          paths[dep] = paths[name] + [dep]
          queue << dep
        end
      end

      paths
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
