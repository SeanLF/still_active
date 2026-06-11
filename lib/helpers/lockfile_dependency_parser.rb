# frozen_string_literal: true

module StillActive
  # Side-effect-free Gemfile.lock parser: extracts each top-level dependency's
  # name, version, and source (type + URI) straight from the lockfile text.
  #
  # We deliberately do NOT load the Gemfile (evaluating it is arbitrary code
  # execution when the audited project is untrusted, e.g. CI on a pull request)
  # and do NOT use Bundler::LockfileParser. The latter is not side-effect-free:
  # a `PLUGIN SOURCE` block runs `Bundler::Plugin.from_lock` at parse time,
  # which resolves against the on-disk plugin registry and can raise or activate
  # an installed plugin. (Bundler's own `@gemfile_parse` guard that neutralizes
  # this is set only inside `Bundler::Plugin.gemfile_install`, never for a
  # standalone parse.) This mirrors what OSV-Scanner and Trivy do for the same
  # threat model, and what `LockfileIndexer` already does here. Refs #37.
  module LockfileDependencyParser
    extend self

    Spec = Struct.new(:name, :version, :source_type, :source_uri, keyword_init: true)

    # Lockfile source blocks and the source_type each maps to. PLUGIN SOURCE is
    # recognized as a block (so its lines are consumed as inert data, not
    # mis-read as specs) but yields no auditable gems.
    SOURCE_TYPES = { "GEM" => :rubygems, "GIT" => :git, "PATH" => :path }.freeze
    PLUGIN_SOURCE = "PLUGIN SOURCE"

    # A section header sits at column 0; Bundler emits them in SCREAMING form.
    SECTION_HEADER = /\A[A-Z]/
    # A top-level spec is indented exactly 4 spaces: `    name (1.2.3)` or, for a
    # platform gem, `    name (1.2.3-x86_64-linux)`. Nested deps (6 spaces) and
    # the `specs:`/`remote:` option lines (2 spaces) do not match. We do NOT
    # anchor the end of the line: Bundler's grammar allows an optional trailing
    # checksum on a spec line, and an audit tool must never silently drop a gem
    # because of unexpected trailing content (that would be a false-negative
    # evasion on a hand-crafted lockfile).
    SPEC_LINE = /\A {4}(\S+) \(([^-)]+)(?:-[^)]*)?\)/
    REMOTE_LINE = /\A {2}remote: (.+)\z/
    # A DEPENDENCIES entry is indented 2 spaces: `  name`, `  name (~> 1.0)`, or
    # `  name!` (the `!` marks a pinned git/path source).
    DEPENDENCY_LINE = /\A {2}([^\s(!]+)/

    # Parses lockfile text into { specs:, direct:, plugin_source? }.
    # `specs` is every locked top-level spec (a Spec per gem); `direct` is the
    # names from the DEPENDENCIES section; `plugin_source?` flags that a
    # PLUGIN SOURCE block was present (and skipped).
    def parse(content)
      specs = []
      direct = []
      section = nil
      source_type = nil
      remote = nil
      plugin_source = false

      content.each_line do |raw|
        line = raw.chomp

        if line.match?(SECTION_HEADER)
          section = line
          source_type = SOURCE_TYPES[line]
          remote = nil
          plugin_source ||= (line == PLUGIN_SOURCE)
          next
        end

        case section
        when "GEM", "GIT", "PATH"
          if (m = REMOTE_LINE.match(line))
            remote ||= m[1] # first remote wins, matching Bundler's remotes.first
          elsif (m = SPEC_LINE.match(line))
            specs << Spec.new(name: m[1], version: m[2], source_type: source_type, source_uri: remote)
          end
        when "DEPENDENCIES"
          if (m = DEPENDENCY_LINE.match(line))
            direct << m[1]
          end
        end
      end

      { specs: specs, direct: direct, plugin_source?: plugin_source }
    end
  end
end
