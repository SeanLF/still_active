# frozen_string_literal: true

require_relative "../../lib/still_active/helpers/sbom_graph"

RSpec.describe(StillActive::SbomGraph) do
  # Pure graph reasoning over CycloneDX bom-refs. Identity (ecosystem/name) is the
  # reader's job, so everything here is refs. The two real generator shapes this
  # has to satisfy were captured from actual output, not invented:
  #
  #   Trivy:  metadata.component (application) -> one application per manifest
  #           (Gemfile.lock, package-lock.json) -> the libraries it declares.
  #           bom-refs are UUIDs.
  #   Syft:   metadata.component is a `file` that is NOT a graph node at all; the
  #           scanned project appears instead as an ordinary library component
  #           with no incoming edge. bom-refs are purls.
  #
  # So "direct" cannot come from metadata.component alone, and cannot assume the
  # root is one hop above the libraries.
  describe(".resolve") do
    it("treats the libraries below a manifest intermediate as direct (the Trivy shape)") do
      result = described_class.resolve(
        dependencies: [
          {"ref" => "root", "dependsOn" => ["manifest"]},
          {"ref" => "manifest", "dependsOn" => ["rails", "rake"]},
          {"ref" => "rails", "dependsOn" => ["activesupport"]}
        ],
        root_ref: "root",
        library_refs: ["rails", "rake", "activesupport"].to_set
      )

      expect(result["rails"][:direct]).to(be(true))
      expect(result["rake"][:direct]).to(be(true))
      expect(result["activesupport"][:direct]).to(be(false))
    end

    it("treats the libraries below an unreferenced project node as direct (the Syft shape)") do
      # metadata.component names a `file` that never appears in the graph; the
      # project is a library with no incoming edge.
      result = described_class.resolve(
        dependencies: [
          {"ref" => "probe", "dependsOn" => ["express"]},
          {"ref" => "express", "dependsOn" => ["body-parser"]}
        ],
        root_ref: "a-file-ref-not-in-the-graph",
        library_refs: ["probe", "express", "body-parser"].to_set
      )

      expect(result["express"][:direct]).to(be(true))
      expect(result["body-parser"][:direct]).to(be(false))
    end

    it("never reports the project's own node as one of its dependencies") do
      result = described_class.resolve(
        dependencies: [{"ref" => "probe", "dependsOn" => ["express"]}],
        root_ref: nil,
        library_refs: ["probe", "express"].to_set
      )

      expect(result).not_to(have_key("probe"))
    end

    it("records the shortest path from the direct dependency that pulls a package in") do
      result = described_class.resolve(
        dependencies: [
          {"ref" => "root", "dependsOn" => ["a"]},
          {"ref" => "a", "dependsOn" => ["b"]},
          {"ref" => "b", "dependsOn" => ["c"]}
        ],
        root_ref: "root",
        library_refs: ["a", "b", "c"].to_set
      )

      # Head names the direct dependency a maintainer can actually act on,
      # matching the native path's dependency_path contract.
      expect(result["c"][:path]).to(eq(["a", "b", "c"]))
      expect(result["b"][:path]).to(eq(["a", "b"]))
    end

    it("gives a direct dependency no path, as the native path does") do
      result = described_class.resolve(
        dependencies: [{"ref" => "root", "dependsOn" => ["a"]}],
        root_ref: "root",
        library_refs: ["a"].to_set
      )

      expect(result["a"][:direct]).to(be(true))
      expect(result["a"][:path]).to(be_nil)
    end

    it("prefers the shortest of several paths to the same package") do
      result = described_class.resolve(
        dependencies: [
          {"ref" => "root", "dependsOn" => ["a", "b"]},
          {"ref" => "a", "dependsOn" => ["deep"]},
          {"ref" => "deep", "dependsOn" => ["target"]},
          {"ref" => "b", "dependsOn" => ["target"]}
        ],
        root_ref: "root",
        library_refs: ["a", "b", "deep", "target"].to_set
      )

      expect(result["target"][:path]).to(eq(["b", "target"]))
    end

    it("reports a package that is both direct and reachable transitively as direct") do
      result = described_class.resolve(
        dependencies: [
          {"ref" => "root", "dependsOn" => ["a", "shared"]},
          {"ref" => "a", "dependsOn" => ["shared"]}
        ],
        root_ref: "root",
        library_refs: ["a", "shared"].to_set
      )

      # You declared it, so it is yours to act on; the transitive edge doesn't
      # demote it.
      expect(result["shared"][:direct]).to(be(true))
      expect(result["shared"][:path]).to(be_nil)
    end

    it("terminates on a dependency cycle") do
      result = described_class.resolve(
        dependencies: [
          {"ref" => "root", "dependsOn" => ["a"]},
          {"ref" => "a", "dependsOn" => ["b"]},
          {"ref" => "b", "dependsOn" => ["a"]}
        ],
        root_ref: "root",
        library_refs: ["a", "b"].to_set
      )

      expect(result["a"][:direct]).to(be(true))
      expect(result["b"][:path]).to(eq(["a", "b"]))
    end

    # The degradation cases. Every one of these must yield nil, meaning "this SBOM
    # cannot answer the question", so the caller omits the fields entirely. The
    # failure that matters is reporting `direct: false` for everything, which reads
    # as the positive claim "none of these are yours" on an SBOM that simply never
    # said.
    it("returns nil when the document carries no dependency graph") do
      expect(described_class.resolve(dependencies: nil, root_ref: "root", library_refs: Set["a"])).to(be_nil)
      expect(described_class.resolve(dependencies: [], root_ref: "root", library_refs: Set["a"])).to(be_nil)
    end

    it("returns nil when the graph has edges but no reachable starting point") do
      # Every node has a parent (fully cyclic), so nothing can be called direct.
      expect(
        described_class.resolve(
          dependencies: [
            {"ref" => "a", "dependsOn" => ["b"]},
            {"ref" => "b", "dependsOn" => ["a"]}
          ],
          root_ref: nil,
          library_refs: ["a", "b"].to_set
        )
      ).to(be_nil)
    end

    it("returns nil when the graph names only components that are not libraries") do
      expect(
        described_class.resolve(
          dependencies: [{"ref" => "root", "dependsOn" => ["manifest"]}],
          root_ref: "root",
          library_refs: Set.new
        )
      ).to(be_nil)
    end

    it("survives a malformed graph rather than raising mid-audit") do
      expect {
        described_class.resolve(
          dependencies: ["nonsense", {"ref" => nil, "dependsOn" => "not-an-array"}, {}],
          root_ref: "root",
          library_refs: Set["a"]
        )
      }.not_to(raise_error)
    end
  end
end
