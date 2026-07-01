# frozen_string_literal: true

RSpec.describe(StillActive::ConstraintHelper) do
  describe(".analyze") do
    # kind classification -------------------------------------------------
    it("reads a bare lower bound as permissive (no ceiling to worry about)") do
      expect(described_class.analyze(requirement: ">= 4.2.0", dep_latest: "8.0.0"))
        .to(eq(kind: :permissive, majors_behind: 0))
    end

    it("reads >= 0, *, and empty as permissive") do
      [">= 0", "*", "", nil, "> 1.0"].each do |req|
        expect(described_class.analyze(requirement: req, dep_latest: "8.0.0")[:kind]).to(eq(:permissive))
      end
    end

    it("reads an exact pin as :exact_pin") do
      ["=4.2.0", "==4.2.0", "===4.2.0"].each do |req|
        expect(described_class.analyze(requirement: req, dep_latest: "8.0.0")[:kind]).to(eq(:exact_pin))
      end
    end

    it("reads a bare version (npm/cargo exact) as :exact_pin") do
      expect(described_class.analyze(requirement: "1.2.3", dep_latest: "3.0.0")[:kind]).to(eq(:exact_pin))
    end

    it("reads an upper bound as :ceiling") do
      ["< 5.0", "<= 5.0", "~> 4.2", "~= 1.4", "^1.2.3", "~1.2.3"].each do |req|
        expect(described_class.analyze(requirement: req, dep_latest: "8.0.0")[:kind]).to(eq(:ceiling))
      end
    end

    # majors_behind (the poison math) ------------------------------------
    it("computes majors behind for a Ruby pessimistic cap (~> A.B => max major A)") do
      # ~> 4.2 allows >= 4.2, < 5.0 -> max major 4; latest major 8 -> 4 behind
      expect(described_class.analyze(requirement: "~> 4.2", dep_latest: "8.0.1")[:majors_behind]).to(eq(4))
    end

    it("computes majors behind for the real poison-pill receipts") do
      # protected_attributes: activemodel "< 5.0, >= 4.0.1", latest 8 -> 4 behind
      expect(described_class.analyze(requirement: ">= 4.0.1, < 5.0", dep_latest: "8.0.1")[:majors_behind]).to(eq(4))
      # therubyracer: libv8 "~> 3.16.14.15", latest 8 -> 5 behind
      expect(described_class.analyze(requirement: "~> 3.16.14.15", dep_latest: "8.4.255")[:majors_behind]).to(eq(5))
      # paperclip: terrapin "~> 0.6.0", latest 1 -> 1 behind
      expect(described_class.analyze(requirement: "~> 0.6.0", dep_latest: "1.0.1")[:majors_behind]).to(eq(1))
    end

    it("treats < X.0.0 as excluding major X (max major X-1), but <= X.0.0 as allowing X") do
      expect(described_class.analyze(requirement: "< 5.0", dep_latest: "8.0.0")[:majors_behind]).to(eq(4)) # max 4
      expect(described_class.analyze(requirement: "<= 5.0", dep_latest: "8.0.0")[:majors_behind]).to(eq(3)) # max 5
      expect(described_class.analyze(requirement: "< 5.5", dep_latest: "8.0.0")[:majors_behind]).to(eq(3)) # max 5
    end

    it("handles semver caret and tilde (max major = the pinned major)") do
      expect(described_class.analyze(requirement: "^1.2.3", dep_latest: "3.0.0")[:majors_behind]).to(eq(2))
      expect(described_class.analyze(requirement: "~1.2.3", dep_latest: "3.0.0")[:majors_behind]).to(eq(2))
    end

    it("handles pip compatible-release ~=") do
      expect(described_class.analyze(requirement: "~= 1.4", dep_latest: "3.0.0")[:majors_behind]).to(eq(2))
    end

    it("computes majors behind for an exact pin too") do
      expect(described_class.analyze(requirement: "= 4.2.0", dep_latest: "8.0.0")[:majors_behind]).to(eq(4))
    end

    it("is 0 behind when the cap is at or above the dep's latest major (not a pill)") do
      expect(described_class.analyze(requirement: "~> 8.0", dep_latest: "8.2.0")[:majors_behind]).to(eq(0))
      expect(described_class.analyze(requirement: "< 9.0", dep_latest: "8.2.0")[:majors_behind]).to(eq(0))
    end

    it("uses the tightest ceiling when several upper bounds are present") do
      expect(described_class.analyze(requirement: "< 7.0, < 5.0", dep_latest: "8.0.0")[:majors_behind]).to(eq(4))
    end

    it("is 0 behind (never negative) and safe when dep_latest is missing or unparseable") do
      expect(described_class.analyze(requirement: "~> 4.2", dep_latest: nil)[:majors_behind]).to(eq(0))
      expect(described_class.analyze(requirement: "~> 4.2", dep_latest: "nonsense")[:majors_behind]).to(eq(0))
    end

    # npm OR-ranges: satisfied by ANY branch, so the effective ceiling is the
    # LOOSEST branch. Reading only the first branch would invent a false pill.
    it("does not flag an OR-range whose looser branch allows the dep's latest major") do
      expect(described_class.analyze(requirement: "^2.0.0 || ^3.0.0", dep_latest: "3.0.0")[:majors_behind]).to(eq(0))
      expect(described_class.analyze(requirement: "^1.0.0 || ^2.0.0 || ^3.0.0", dep_latest: "3.1.0")[:majors_behind]).to(eq(0))
    end

    it("treats an OR-range with an unbounded branch as permissive (that branch lifts the cap)") do
      expect(described_class.analyze(requirement: "< 2.0.0 || >= 3.0.0", dep_latest: "3.0.0"))
        .to(eq(kind: :permissive, majors_behind: 0))
    end

    it("still flags an OR-range where EVERY branch caps below the latest major") do
      # both branches cap at <=2.x; latest 5 -> 3 behind (loosest branch = ^2.0.0 -> major 2)
      expect(described_class.analyze(requirement: "^1.0.0 || ^2.0.0", dep_latest: "5.0.0")[:majors_behind]).to(eq(3))
    end

    it("reads an npm space-separated AND range (>=x <y) as a ceiling, not permissive") do
      expect(described_class.analyze(requirement: ">=1.2.0 <2.0.0", dep_latest: "3.0.0"))
        .to(eq(kind: :ceiling, majors_behind: 2))
    end

    # rb/polynomial-redos: the requirement string is lockfile-derived, so a gem
    # could publish a pathological one. A huge run of whitespace must not hang the
    # AND-clause split; it is over-length garbage, so it reads as permissive.
    it("returns permissive immediately for a pathological all-whitespace requirement (no ReDoS)") do
      expect(described_class.analyze(requirement: " " * 100_000, dep_latest: "8.0.0"))
        .to(eq(kind: :permissive, majors_behind: 0))
    end

    it("treats an over-long requirement string as permissive (never mints a pill from garbage)") do
      long_ceilingish = "#{"< 5.0," * 100} < 5.0"
      expect(long_ceilingish.length).to(be > described_class::MAX_REQUIREMENT_LENGTH)
      expect(described_class.analyze(requirement: long_ceilingish, dep_latest: "8.0.0"))
        .to(eq(kind: :permissive, majors_behind: 0))
    end
  end

  describe(".poison_findings") do
    let(:latest) { { "activemodel" => "8.0.1", "terrapin" => "1.1.1", "rack" => "3.1.0" } }

    def resolve = ->(name) { latest[name] }

    it("returns a receipt for each below-latest ceiling / exact pin, skipping the rest") do
      deps = [
        { package_name: "activemodel", requirements: "< 5.0" },     # ceiling, 4 behind
        { package_name: "terrapin", requirements: "~> 0.6.0" },     # ceiling, 1 behind
        { package_name: "rack", requirements: ">= 2.0" },           # permissive -> skipped
      ]

      findings = described_class.poison_findings(deps, &resolve)

      expect(findings).to(eq([
        { dependency: "activemodel", requirement: "< 5.0", dep_latest: "8.0.1", majors_behind: 4, kind: :ceiling },
        { dependency: "terrapin", requirement: "~> 0.6.0", dep_latest: "1.1.1", majors_behind: 1, kind: :ceiling },
      ]))
    end

    it("drops a dep whose latest the resolver cannot determine (returns nil), rather than guessing") do
      deps = [{ package_name: "ghost", requirements: "< 5.0" }]
      expect(described_class.poison_findings(deps) { nil }).to(eq([]))
    end
  end

  describe(".top_findings") do
    def finding(dep, behind)
      { dependency: dep, requirement: "< x", dep_latest: "9.0.0", majors_behind: behind, kind: :ceiling }
    end

    it("returns the worst `limit` findings (majors_behind desc) plus the full total") do
      findings = [finding("a", 1), finding("b", 4), finding("c", 2), finding("d", 3)]

      result = described_class.top_findings(findings, limit: 3)

      expect(result[:total]).to(eq(4))
      expect(result[:shown].map { |f| f[:dependency] }).to(eq(["b", "d", "c"])) # 4, 3, 2
    end

    it("breaks majors_behind ties by dependency name ascending, for a stable/diffable order") do
      findings = [finding("vinyl", 3), finding("array-differ", 3), finding("through2", 3)]

      result = described_class.top_findings(findings, limit: 3)

      expect(result[:shown].map { |f| f[:dependency] }).to(eq(["array-differ", "through2", "vinyl"]))
    end

    it("returns all findings when there are fewer than the limit") do
      findings = [finding("a", 2), finding("b", 1)]
      result = described_class.top_findings(findings, limit: 3)
      expect(result).to(eq(shown: [finding("a", 2), finding("b", 1)], total: 2))
    end

    it("handles an empty list") do
      expect(described_class.top_findings([], limit: 3)).to(eq(shown: [], total: 0))
    end
  end

  describe("severity") do
    def ceiling(behind)
      { dependency: "d", requirement: "< x", dep_latest: "9.0.0", majors_behind: behind, kind: :ceiling }
    end

    it("tiers a ceiling by magnitude: 1 behind = note, 2 = warning, 3+ = critical") do
      expect(described_class.constraint_severity(ceiling(1))).to(eq(:note))
      expect(described_class.constraint_severity(ceiling(2))).to(eq(:warning))
      expect(described_class.constraint_severity(ceiling(3))).to(eq(:critical))
      expect(described_class.constraint_severity(ceiling(5))).to(eq(:critical))
    end

    it("rolls a gem's ceilings up to its worst tier (exact-pins excluded)") do
      findings = [ceiling(1), ceiling(3), { dependency: "e", kind: :exact_pin, majors_behind: 9 }]
      expect(described_class.worst_severity(findings)).to(eq(:critical))
    end

    it("returns nil worst_severity when there are no ceilings") do
      expect(described_class.worst_severity([{ kind: :exact_pin, majors_behind: 4 }])).to(be_nil)
    end

    it("compares severities by ordinal for the gate threshold") do
      expect(described_class.severity_at_or_above?(:critical, :warning)).to(be(true))
      expect(described_class.severity_at_or_above?(:note, :warning)).to(be(false))
      expect(described_class.severity_at_or_above?(:warning, :warning)).to(be(true))
      expect(described_class.severity_at_or_above?(nil, :note)).to(be(false))
    end
  end

  describe(".poison_ceiling?") do
    it("is true only for a below-latest ceiling or exact pin") do
      expect(described_class.poison_ceiling?(requirement: "~> 4.2", dep_latest: "8.0.0")).to(be(true))
      expect(described_class.poison_ceiling?(requirement: "= 4.2.0", dep_latest: "8.0.0")).to(be(true))
      expect(described_class.poison_ceiling?(requirement: ">= 4.2.0", dep_latest: "8.0.0")).to(be(false)) # permissive
      expect(described_class.poison_ceiling?(requirement: "~> 8.0", dep_latest: "8.2.0")).to(be(false)) # at latest
    end
  end
end
