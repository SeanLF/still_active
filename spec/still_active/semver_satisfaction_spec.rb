# frozen_string_literal: true

require_relative "../../lib/helpers/semver_satisfaction"

RSpec.describe(StillActive::SemverSatisfaction) do
  # Vectors are transcribed from the ecosystems' own suites: node-semver's
  # test/fixtures/range-{include,exclude}.js for npm, and dtolnay/semver's
  # tests/test_version_req.rs for cargo. The point of this primitive is PATCH
  # precision: a CVE fix is usually a same-major patch bump, so "does this fixed
  # version escape the declared constraint" can't be answered at major precision.
  def satisfies?(requirement, version, ecosystem)
    described_class.evaluate(requirement: requirement, version: version, ecosystem: ecosystem)
  end

  describe "npm (node-semver semantics)" do
    it "matches caret at patch precision" do
      expect(satisfies?("^2.3.1", "2.3.2", :npm)).to(be(true))
      expect(satisfies?("^2.3.1", "2.9.9", :npm)).to(be(true))
      expect(satisfies?("^2.3.1", "3.0.0", :npm)).to(be(false))
    end

    it "applies node-semver's 0.x caret rule" do
      expect(satisfies?("^0.2.3", "0.2.9", :npm)).to(be(true))
      expect(satisfies?("^0.2.3", "0.3.0", :npm)).to(be(false))
      expect(satisfies?("^0.0.3", "0.0.3", :npm)).to(be(true))
      expect(satisfies?("^0.0.3", "0.0.4", :npm)).to(be(false))
    end

    it "handles tilde and OR ranges" do
      expect(satisfies?("~1.2.3", "1.2.9", :npm)).to(be(true))
      expect(satisfies?("~1.2.3", "1.3.0", :npm)).to(be(false))
      expect(satisfies?("1.2.0 || ^3.0.0", "3.5.0", :npm)).to(be(true))
      expect(satisfies?("1.2.0 || ^3.0.0", "2.0.0", :npm)).to(be(false))
    end

    it "excludes a prerelease outside the constraint's own tuple (node-semver rule)" do
      expect(satisfies?("^1.2.3", "2.0.0-beta", :npm)).to(be(false))
    end

    it "reads a bare full version as EXACT (npm), not a range" do
      expect(satisfies?("1.2.3", "1.2.3", :npm)).to(be(true))
      expect(satisfies?("1.2.3", "1.2.4", :npm)).to(be(false))
    end

    it "handles x-ranges and bare comparators" do
      expect(satisfies?("1.x", "1.5.0", :npm)).to(be(true))
      expect(satisfies?("1.x", "2.0.0", :npm)).to(be(false))
      expect(satisfies?(">=1.2.0 <2.0.0", "1.9.0", :npm)).to(be(true))
    end

    it "admits a prerelease that shares the constraint's tuple" do
      expect(satisfies?("^1.2.3-alpha", "1.2.3-beta", :npm)).to(be(true))
    end
  end

  describe "cargo (Cargo VersionReq semantics)" do
    it "reads a bare full version as a CARET, the sole divergence from npm" do
      # dtolnay/semver test_basic: req("1.0.0") displays as ^1.0.0 and matches 1.1.0.
      # This is the case the security signal must get right: a same-minor patch fix
      # under a bare cargo requirement is REACHABLE, so it is NOT below the fix.
      expect(satisfies?("0.10.38", "0.10.40", :cargo)).to(be(true))
      expect(satisfies?("1.0.0", "1.1.0", :cargo)).to(be(true))
      expect(satisfies?("1.0.0", "2.0.0", :cargo)).to(be(false))
    end

    it "contrasts with npm, where the same bare version is exact and would NOT match" do
      expect(satisfies?("0.10.38", "0.10.40", :npm)).to(be(false))
      expect(satisfies?("0.10.38", "0.10.40", :cargo)).to(be(true))
    end

    it "agrees with npm on explicit caret (including 0.x) and on partial bares" do
      expect(satisfies?("^0.2.0", "0.2.3", :cargo)).to(be(true))
      expect(satisfies?("^0.2.0", "0.3.0", :cargo)).to(be(false))
      expect(satisfies?("1.2", "1.2.9", :cargo)).to(be(true))
      expect(satisfies?("1.2", "1.3.0", :cargo)).to(be(false))
    end

    it "honours an explicit exact requirement" do
      expect(satisfies?("=1.2.3", "1.2.4", :cargo)).to(be(false))
      expect(satisfies?("=1.2.3", "1.2.3", :cargo)).to(be(true))
    end

    it "reads a bare full version carrying BOTH prerelease and build metadata as a caret" do
      # 1.2.3-alpha+001 is a valid full semver; a bare cargo version is still a caret,
      # so it must match a later same-major release, where npm's exact pin would not.
      expect(satisfies?("1.2.3-alpha+001", "1.5.0", :cargo)).to(be(true))
      expect(satisfies?("1.2.3-alpha+001", "1.5.0", :npm)).to(be(false))
    end

    it "handles comma-separated AND clauses and the wildcard" do
      expect(satisfies?(">=1.0, <1.5", "1.2.0", :cargo)).to(be(true))
      expect(satisfies?(">=1.0, <1.5", "1.6.0", :cargo)).to(be(false))
      expect(satisfies?("*", "9.9.9", :cargo)).to(be(true))
    end
  end

  describe "undecidable input (fail safe, never a false 'unreachable')" do
    # semantic_range returns false for garbage, which in a wall test reads as
    # "fix unreachable" -> a false below-the-fix flag. The primitive returns nil
    # instead so the caller can refuse to flag on input it couldn't parse.
    it "returns nil for an unparseable requirement" do
      expect(satisfies?("not-a-range", "1.0.0", :npm)).to(be_nil)
    end

    it "returns nil for an unparseable version" do
      expect(satisfies?("^1.0.0", "garbage", :npm)).to(be_nil)
    end

    it "returns nil for an unsupported ecosystem (no assumed semantics)" do
      expect(satisfies?("^1.0.0", "1.2.0", :rubygems)).to(be_nil)
    end

    it "returns nil for a blank or missing requirement (missing data, not 'anything satisfies')" do
      # semantic_range reads an empty range as `*` (matches everything). A missing
      # requirement in our data is a failed extraction, not a package that allows any
      # version, so it must stay undecidable -- symmetric with a missing version.
      expect(satisfies?(nil, "1.0.0", :npm)).to(be_nil)
      expect(satisfies?("", "1.0.0", :npm)).to(be_nil)
      expect(satisfies?("   ", "9.9.9", :cargo)).to(be_nil)
    end
  end
end
