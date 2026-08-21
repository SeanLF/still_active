# frozen_string_literal: true

module StillActive
  # Direct-vs-transitive reasoning over a CycloneDX `dependencies` graph.
  #
  # The native Bundler audit knows which gems you declared and, for the rest, the
  # shortest path back to the declared gem that pulls them in, which is what turns
  # an un-actionable transitive finding into "replace your direct dep A". The SBOM
  # path had no equivalent: every package read the same, whether you chose it or it
  # arrived six levels down. CycloneDX carries the graph to answer this; still_active
  # simply never read it.
  #
  # This works purely in bom-refs. Turning a ref into an `ecosystem/name` identity
  # is the reader's job, so this stays a graph problem with no purl knowledge.
  #
  # Two real generator shapes have to work, both captured from actual output rather
  # than assumed:
  #
  #   Trivy: `metadata.component` is an application, whose children are one
  #          application per manifest found (Gemfile.lock, package-lock.json), whose
  #          children are the libraries that manifest declares. bom-refs are UUIDs.
  #   Syft:  `metadata.component` is a `file` that is not a graph node at all. The
  #          scanned project appears instead as an ordinary library component with
  #          no incoming edge. bom-refs are purls.
  #
  # So "direct" can be neither "child of metadata.component" nor "one hop from the
  # root". What holds for both: start at the graph's entry points, descend through
  # any non-library scaffolding, and the FIRST library reached on each path is a
  # declared dependency.
  module SbomGraph
    extend self

    # => { ref => {direct: bool, path: [ref, ...] | nil} }, or nil when this SBOM
    # cannot answer the question. nil is not "nothing is direct": callers must omit
    # the fields entirely, because emitting `direct: false` everywhere would be the
    # positive claim "none of these are yours" about a document that never said.
    def resolve(dependencies:, root_ref:, library_refs:)
      edges = edges_from(dependencies)
      return if edges.empty?

      entries = entry_points(edges, root_ref)
      return if entries.empty?

      direct = direct_libraries(edges, entries, library_refs)
      return if direct.empty?

      paths = shortest_paths(edges, direct, library_refs)
      resolved = {}
      direct.each { |ref| resolved[ref] = {direct: true, path: nil} }
      paths.each { |ref, path| resolved[ref] ||= {direct: false, path: path} }
      resolved
    end

    # The library components that are the scanned project(s) rather than
    # dependencies of one. A Syft SBOM lists the project as an ordinary library
    # with a purl, indistinguishable from a dependency by shape alone, so
    # still_active audited the user's own code and reported it as critically
    # stale (it has no registry entry, so it looks abandoned).
    #
    # The graph tells them apart: the project is what nothing depends on. The rule
    # is deliberately conservative on both halves. It requires an OUTGOING edge, so
    # a dependency whose parent edge the generator simply failed to record stays a
    # dependency rather than vanishing from the audit, and it only ever considers
    # libraries, so Trivy's application-typed root and manifest nodes (never
    # dependencies to begin with) are not reported here. A merged SBOM covering
    # several projects yields all of them.
    def project_refs(dependencies:, library_refs:)
      edges = edges_from(dependencies)
      return Set.new if edges.empty?

      pointed_at = Set.new
      edges.each_value { |children| pointed_at.merge(children) }

      edges.each_with_object(Set.new) do |(ref, children), roots|
        next unless library_refs.include?(ref)
        next if pointed_at.include?(ref)
        next if children.empty?

        roots << ref
      end
    end

    private

    # {ref => [child refs]}, skipping anything malformed. A generator is free to
    # emit an entry with no dependsOn; that is a leaf, not an error.
    def edges_from(dependencies)
      return {} unless dependencies.is_a?(Array)

      dependencies.each_with_object({}) do |entry, edges|
        next unless entry.is_a?(Hash)

        ref = entry["ref"]
        next unless ref.is_a?(String)

        children = entry["dependsOn"]
        edges[ref] = children.is_a?(Array) ? children.grep(String) : []
      end
    end

    # Where a walk can start: the declared root when it is actually a node, plus
    # every node nothing points at. The second clause is what rescues the Syft
    # shape, where the declared root is a file that never appears in the graph and
    # the project node is simply parentless.
    def entry_points(edges, root_ref)
      pointed_at = Set.new
      edges.each_value { |children| pointed_at.merge(children) }

      entries = edges.keys.reject { |ref| pointed_at.include?(ref) }
      entries << root_ref if root_ref.is_a?(String) && edges.key?(root_ref) && !entries.include?(root_ref)
      entries
    end

    # Descend from the entry points through non-library scaffolding (Trivy's
    # per-manifest application nodes) and collect the first library on each path.
    # The entry points themselves are never direct: they are the project, or a
    # manifest, and in the Syft shape the project node IS a library.
    def direct_libraries(edges, entries, library_refs)
      direct = Set.new
      seen = Set.new(entries)
      queue = entries.dup

      until queue.empty?
        (edges[queue.shift] || []).each do |child|
          next if seen.include?(child)

          seen << child
          if library_refs.include?(child)
            direct << child
          else
            queue << child
          end
        end
      end

      direct
    end

    # BFS over library edges from the direct set, so each transitive package gets
    # the shortest chain back to the declared dependency that pulls it in, head
    # first. Same contract as the native path's dependency_path.
    def shortest_paths(edges, direct, library_refs)
      paths = {}
      queue = []
      direct.each do |ref|
        paths[ref] = [ref]
        queue << ref
      end

      until queue.empty?
        ref = queue.shift
        (edges[ref] || []).each do |child|
          next unless library_refs.include?(child)
          next if paths.key?(child)

          paths[child] = paths[ref] + [child]
          queue << child
        end
      end

      # The direct set seeded this BFS, so drop it: a declared dependency carries
      # no path, matching the native path's contract.
      paths.except(*direct)
    end
  end
end
