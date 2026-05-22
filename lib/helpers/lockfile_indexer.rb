# frozen_string_literal: true

module StillActive
  # Maps gem names to line numbers in a Bundler-generated Gemfile.lock.
  # Used by SARIF output so findings annotate the correct lockfile line.
  #
  # We hand-roll the parsing rather than delegating to
  # Bundler::LockfileParser because the latter is not side-effect-free —
  # it tries to resolve PLUGIN SOURCE blocks against the installed plugin
  # registry and raises Bundler::Plugin::UnknownSourceError if a plugin
  # isn't present in the consuming environment. We just want names + lines.
  module LockfileIndexer
    extend self

    # Bundler indents top-level specs with exactly 4 spaces; nested deps get
    # 6+. \S+ matches what Bundler's own parser accepts (any non-space).
    TOP_LEVEL_SPEC = /\A    (\S+) \(/
    # Source blocks Bundler emits — see bundler/lockfile_parser.rb SOURCE constant.
    BLOCK_HEADER = /\A(GEM|GIT|PATH|PLUGIN SOURCE)\b/
    SECTION_BREAK = /\A[A-Z]/

    # Returns a Hash mapping gem name -> 1-based line number in `content`.
    # When a gem appears as both a top-level spec and a nested dep, the
    # top-level entry wins. Lines outside GEM/GIT/PATH/PLUGIN SOURCE blocks
    # are ignored.
    def gem_line_index(content)
      index = {}
      in_block = false
      content.each_line.with_index(1) do |line, lineno|
        if line.match?(BLOCK_HEADER)
          in_block = true
          next
        end
        if line.match?(SECTION_BREAK)
          in_block = false
          next
        end
        next unless in_block

        match = line.match(TOP_LEVEL_SPEC)
        index[match[1]] = lineno if match
      end
      index
    end

    # Returns the 1-based line number of the Ruby version inside the
    # RUBY VERSION block (the line *after* the header). Falls back to 1.
    def ruby_version_line(content)
      content.each_line.with_index(1) do |line, lineno|
        return lineno + 1 if line.start_with?("RUBY VERSION")
      end
      1
    end
  end
end
