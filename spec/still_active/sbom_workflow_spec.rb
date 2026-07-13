# frozen_string_literal: true

RSpec.describe(StillActive::SbomWorkflow) do
  before { StillActive.reset }

  def result_with(dependencies, unassessable: [])
    StillActive::SbomReader::Result.new(dependencies: dependencies, unassessable: unassessable)
  end

  describe(".call") do
    it("reconciles a language ceiling against a poison cap end-to-end, on the assembled key/name shape (not a hand-built hash)") do
      # The reconciler's cross-path contract (data[:name] + "ecosystem/name@version"
      # keys) is unit-tested with hand-built hashes; this exercises it through the
      # REAL SbomWorkflow assembly, so a drift in the gem_data shape (e.g. assess
      # stops setting :name) can't pass green. `foo` carries a Python ceiling that
      # says "upgrade to lift it"; `bar` poison-caps `foo` below that upgrade, so the
      # reconcile must clear fixed_by_upgrade and set upgrade_blocked.
      allow(StillActive::PythonHelper).to(receive(:supported_python_range).and_return(nil))
      allow(StillActive::DotnetHelper).to(receive_messages(supported_dotnet_range: nil, supported_dotnetfx_range: nil))
      allow(StillActive::EcosystemLens).to(receive(:assess)) do |ecosystem:, name:, version:, **_|
        base = { ecosystem:, name:, version_used: version }
        if name == "foo"
          base.merge(language_ceiling: { runtime: "Python", eol_forced: true, fixed_by_upgrade: true, requirement: "< 3.10" })
        else
          base.merge(constraints: [{ dependency: "foo", requirement: "< 1.0", dep_latest: "2.0.0", majors_behind: 2, kind: :ceiling }])
        end
      end

      out = described_class.call(result_with([
        { ecosystem: :pypi, name: "foo", version: "1.0.0" },
        { ecosystem: :pypi, name: "bar", version: "0.1.0" },
      ]))

      ceiling = out.assessed["pypi/foo@1.0.0"][:language_ceiling]
      expect(ceiling[:fixed_by_upgrade]).to(be(false))
      expect(ceiling[:upgrade_blocked]).to(be(true))
    end

    it("runs the lens over each dependency, keyed by ecosystem/name@version") do
      deps = [
        { ecosystem: :npm, name: "express", version: "5.2.1" },
        { ecosystem: :pypi, name: "requests", version: "2.32.5" },
      ]
      allow(StillActive::EcosystemLens).to(receive(:assess)) { |ecosystem:, name:, version:, **_| { ecosystem:, name:, version_used: version } }

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
      allow(StillActive::EcosystemLens).to(receive(:assess)) { |ecosystem:, name:, version:, **_| { ecosystem:, name:, version_used: version } }

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
      allow(StillActive::EcosystemLens).to(receive(:assess)) { |ecosystem:, name:, version:, **_| { ecosystem:, name:, version_used: version } }

      out = described_class.call(result_with(deps))

      expect(out.assessed.keys).to(contain_exactly("pypi/attrs@25.4.0", "pypi/attrs@26.1.0"))
      expect(out.assessed.values.map { |v| v[:version_used] }).to(contain_exactly("25.4.0", "26.1.0"))
    end

    it("keeps assessing the rest when one dependency's lens raises, and reports the failure instead of dropping it") do
      deps = [
        { ecosystem: :npm, name: "good", version: "1.0.0" },
        { ecosystem: :cargo, name: "boom", version: "0.1.0" },
      ]
      allow(StillActive::EcosystemLens).to(receive(:assess)) do |ecosystem:, name:, version:, **_|
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

    it("threads a dependency's production flag through to its assessed entry") do
      # SbomReader marks production vs dev/test when the SBOM says so; that verdict
      # has to reach the output so a consumer can separate prod risk from test debt.
      deps = [
        { ecosystem: :npm, name: "express", version: "5.2.1", production: true },
        { ecosystem: :npm, name: "jest", version: "29.7.0", production: false },
      ]
      allow(StillActive::EcosystemLens).to(receive(:assess)) { |ecosystem:, name:, version:, **_| { ecosystem:, name:, version_used: version } }

      out = described_class.call(result_with(deps))

      expect(out.assessed["npm/express@5.2.1"]).to(include(production: true))
      expect(out.assessed["npm/jest@29.7.0"]).to(include(production: false))
    end

    it("omits the production key entirely when the SBOM never marked prod/dev (unknown, not false)") do
      # A syft-style SBOM carries no scope: SbomReader leaves the key absent. The
      # workflow must not invent a `production: nil` -- absent means unknown, and a
      # false would wrongly read as "test-only".
      deps = [{ ecosystem: :npm, name: "lodash", version: "4.17.21" }]
      allow(StillActive::EcosystemLens).to(receive(:assess)) { |ecosystem:, name:, version:, **_| { ecosystem:, name:, version_used: version } }

      out = described_class.call(result_with(deps))

      expect(out.assessed["npm/lodash@4.17.21"]).not_to(have_key(:production))
    end

    it("preserves the production flag on a dependency whose lens raises") do
      # A failed prod dependency must stay distinguishable from a failed dev one, so
      # the failure entry carries the same production verdict as an assessed one.
      deps = [{ ecosystem: :cargo, name: "boom", version: "0.1.0", production: true }]
      allow(StillActive::EcosystemLens).to(receive(:assess)) { raise "kaboom" }

      out = described_class.call(result_with(deps))

      expect(out.failures).to(contain_exactly(
        include(ecosystem: :cargo, name: "boom", version: "0.1.0", reason: :assessment_error, production: true),
      ))
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
