# frozen_string_literal: true

require "json"

# Real output from real SBOM generators, committed verbatim.
#
# The README says "from Syft, Trivy, or any producer", and every SBOM bug found so
# far came from a generator disagreeing with the one we happened to test against:
# the scanned project being audited as its own dependency, and direct-vs-transitive
# being underivable from any single generator's convention. A synthetic fixture
# cannot catch those, because whoever writes it writes the shape they already have
# in mind.
#
# So these are not hand-written. Each is the untouched output of running the tool
# against one tiny npm project (`is-odd@3.0.1`, which pulls `is-number@6.0.0`), or
# for cyclonedx-py a one-line requirements file. They disagree about nearly
# everything a reader could naively depend on, which is the point:
#
#   generator        spec   metadata.component   bom-ref convention
#   syft             1.7    file (NOT in graph)  pkg:npm/...?package-id=...
#   trivy            1.7    application          UUID
#   npm sbom         1.5    library              name@version
#   cyclonedx-npm    1.6    application          parent@ver|child@ver
#   cyclonedx-py     1.6    absent               requirements-L1
#
# The four npm generators describe the SAME two packages, so they must produce the
# same verdict. If a change makes one of them disagree, that is the bug.
RSpec.describe("SBOM generator conformance") do # rubocop:disable RSpec/DescribeClass -- the contract spans SbomReader and SbomGraph
  def fixture(name) = File.expand_path("../fixtures/sbom/generators/#{name}.cdx.json", __dir__)

  def read(name) = StillActive::SbomReader.parse(fixture(name))

  # The four that describe the identical npm project. A plain method rather than a
  # constant so it does not leak out of the example group.
  def self.npm_generators = ["syft", "trivy", "npm-sbom", "cyclonedx-npm"]

  def npm_generators = self.class.npm_generators

  # Negative control on the fixture set itself. If these ever collapse to one
  # shape, the four examples below stop being four tests and quietly become one,
  # while still passing. That is the failure mode a table-driven suite has.
  it("keeps genuinely different generator shapes, so this is not one test run four times") do
    docs = npm_generators.map { |name| JSON.parse(File.read(fixture(name))) }

    expect(docs.map { |d| d["specVersion"] }.uniq.size).to(be > 1, "all fixtures share a spec version")
    expect(docs.map { |d| d.dig("metadata", "component", "type") }.uniq.size).to(be > 1, "all fixtures share a metadata.component type")
    # The bom-ref convention is the one that actually broke things, so it gets the
    # strictest check: every generator must use a distinct one.
    first_refs = docs.map { |d| d["components"].first["bom-ref"] }
    expect(first_refs.uniq.size).to(eq(first_refs.size), "two generators now share a bom-ref convention: #{first_refs.inspect}")
  end

  npm_generators.each do |generator|
    context("with #{generator}") do
      subject(:dependencies) { read(generator).dependencies }

      it("audits the two real packages and nothing else") do
        expect(dependencies.map { |d| d[:name] }.sort).to(eq(["is-number", "is-odd"]))
      end

      it("never audits the scanned project as one of its own dependencies") do
        # Syft and npm sbom both list the project as an ordinary library component
        # with a purl; cyclonedx-npm and trivy keep it out of `components`. Either
        # way it must not appear as a dependency, or the user's own code gets a
        # maintenance verdict.
        expect(dependencies.map { |d| d[:name] }).not_to(include("fixture-project"))
      end

      it("reads the declared package as direct and the other as transitive") do
        by_name = dependencies.to_h { |d| [d[:name], d] }

        expect(by_name["is-odd"][:direct]).to(be(true))
        expect(by_name["is-number"][:direct]).to(be(false))
      end

      it("names the direct package that pulls the transitive one in, head first") do
        path = dependencies.find { |d| d[:name] == "is-number" }[:dependency_path]

        expect(path).to(eq(["npm/is-odd", "npm/is-number"]))
      end

      it("gives the direct package no dependency_path") do
        expect(dependencies.find { |d| d[:name] == "is-odd" }).not_to(have_key(:dependency_path))
      end

      it("preserves each package's own purl for re-emission") do
        expect(dependencies.map { |d| d[:purl] }.sort).to(eq(["pkg:npm/is-number@6.0.0", "pkg:npm/is-odd@3.0.1"]))
      end

      it("surfaces nothing as unassessable") do
        expect(read(generator).unassessable).to(be_empty)
      end
    end
  end

  # A generator whose `dependencies` array carries no edges at all. Not a
  # hypothetical: this is what cyclonedx-py emits from a requirements file.
  context("with cyclonedx-py, which emits a dependency graph with no edges") do
    subject(:dependencies) { read("cyclonedx-py").dependencies }

    it("still audits the package") do
      expect(dependencies.map { |d| d[:name] }).to(eq(["requests"]))
    end

    it("claims nothing about direct-vs-transitive rather than guessing") do
      # The failure that matters: `direct: false` here would be the positive claim
      # "this is not one of yours" about a document that never said. Absent is the
      # only honest answer.
      expect(dependencies.first).not_to(have_key(:direct))
      expect(dependencies.first).not_to(have_key(:dependency_path))
    end
  end

  it("never raises on any generator's output, whatever its shape") do
    (npm_generators + ["cyclonedx-py"]).each do |generator|
      expect { read(generator) }.not_to(raise_error)
    end
  end
end
