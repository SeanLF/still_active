# frozen_string_literal: true

RSpec.describe(StillActive::SbomWorkflow) do
  before { StillActive.reset }

  def result_with(dependencies, unassessable: [])
    StillActive::SbomReader::Result.new(dependencies: dependencies, unassessable: unassessable)
  end

  describe(".call") do
    it("runs the lens over each dependency, keyed by ecosystem/name@version") do
      deps = [
        { ecosystem: :npm, name: "express", version: "5.2.1" },
        { ecosystem: :pypi, name: "requests", version: "2.32.5" },
      ]
      allow(StillActive::EcosystemLens).to(receive(:assess)) { |ecosystem:, name:, version:| { ecosystem:, name:, version_used: version } }

      out = described_class.call(result_with(deps))

      expect(out.assessed.keys).to(eq(["npm/express@5.2.1", "pypi/requests@2.32.5"]))
      expect(out.assessed["npm/express@5.2.1"]).to(include(ecosystem: :npm, name: "express", version_used: "5.2.1"))
      expect(out.failures).to(be_empty)
    end

    it("does not let an npm and a pypi package of the same name collide") do
      deps = [
        { ecosystem: :npm, name: "foo", version: "1.0.0" },
        { ecosystem: :pypi, name: "foo", version: "2.0.0" },
      ]
      allow(StillActive::EcosystemLens).to(receive(:assess)) { |ecosystem:, name:, version:| { ecosystem:, name:, version_used: version } }

      out = described_class.call(result_with(deps))

      expect(out.assessed.keys).to(contain_exactly("npm/foo@1.0.0", "pypi/foo@2.0.0"))
      expect(out.assessed["npm/foo@1.0.0"][:version_used]).to(eq("1.0.0"))
      expect(out.assessed["pypi/foo@2.0.0"][:version_used]).to(eq("2.0.0"))
    end

    it("keeps both versions when a monorepo SBOM pins the same package twice") do
      # Two subprojects each vendor `attrs` at a different version. Keyed by bare
      # name they'd collide and one verdict would be silently dropped; keyed by
      # ecosystem/name@version both survive with their own assessment.
      deps = [
        { ecosystem: :pypi, name: "attrs", version: "25.4.0" },
        { ecosystem: :pypi, name: "attrs", version: "26.1.0" },
      ]
      allow(StillActive::EcosystemLens).to(receive(:assess)) { |ecosystem:, name:, version:| { ecosystem:, name:, version_used: version } }

      out = described_class.call(result_with(deps))

      expect(out.assessed.keys).to(contain_exactly("pypi/attrs@25.4.0", "pypi/attrs@26.1.0"))
      expect(out.assessed.values.map { |v| v[:version_used] }).to(contain_exactly("25.4.0", "26.1.0"))
    end

    it("keeps assessing the rest when one dependency's lens raises, and reports the failure instead of dropping it") do
      deps = [
        { ecosystem: :npm, name: "good", version: "1.0.0" },
        { ecosystem: :cargo, name: "boom", version: "0.1.0" },
      ]
      allow(StillActive::EcosystemLens).to(receive(:assess)) do |ecosystem:, name:, version:|
        raise "kaboom" if name == "boom"

        { ecosystem:, name:, version_used: version }
      end

      out = described_class.call(result_with(deps))

      expect(out.assessed.keys).to(eq(["npm/good@1.0.0"]))
      # The raised dep is surfaced as a failure, not silently gone: it must reach
      # the report so the audit can't read "all clear" while skipping it.
      expect(out.failures).to(contain_exactly(
        include(ecosystem: :cargo, name: "boom", version: "0.1.0", reason: :assessment_error),
      ))
      expect(out.failures.first[:error]).to(include("kaboom"))
    end

    it("reports progress as each dependency completes") do
      deps = [{ ecosystem: :npm, name: "a", version: "1" }, { ecosystem: :npm, name: "b", version: "1" }]
      allow(StillActive::EcosystemLens).to(receive(:assess).and_return({}))
      seen = []

      described_class.call(result_with(deps)) { |done, total| seen << [done, total] }

      expect(seen).to(contain_exactly([1, 2], [2, 2]))
    end

    it("returns empty assessed and failures for an SBOM with no assessable dependencies") do
      out = described_class.call(result_with([]))
      expect(out.assessed).to(eq({}))
      expect(out.failures).to(be_empty)
    end
  end
end
