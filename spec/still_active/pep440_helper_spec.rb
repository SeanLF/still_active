# frozen_string_literal: true

require_relative "../../lib/still_active/helpers/pep440_helper"

RSpec.describe(StillActive::Pep440Helper) do
  # The shim translates a PEP 440 `requires_python` specifier into a RubyGems
  # requirement STRING that Gem::Requirement can parse, so the generic
  # RuntimeCeilingHelper can reason about Python ceilings with no code change.
  # We assert SEMANTICS (which Python versions the translation admits/rejects),
  # not the exact string, since several PEP 440 operators have no literal
  # RubyGems spelling.
  subject(:translate) { ->(spec) { described_class.to_gem_requirement_string(spec) } }

  # Build a Gem::Requirement from the translated string the way the core does
  # (split on comma, splat) and ask whether it admits a Python version.
  def admits?(spec, python_version)
    string = translate.call(spec)
    return :untranslatable if string.nil?

    clauses = string.split(",").map(&:strip)
    Gem::Requirement.new(*clauses).satisfied_by?(Gem::Version.new(python_version))
  end

  describe "simple comparison operators pass through" do
    it "keeps a lower-bound floor" do
      expect(admits?(">=3.7", "3.7")).to(be(true))
      expect(admits?(">=3.7", "3.13")).to(be(true))
      expect(admits?(">=3.7", "3.6")).to(be(false))
    end

    it "keeps an upper-bound cap" do
      expect(admits?("<3.11", "3.10")).to(be(true))
      expect(admits?("<3.11", "3.11")).to(be(false))
    end

    it "tolerates whitespace around the operator" do
      expect(admits?(">= 3.7", "3.8")).to(be(true))
      expect(admits?(">= 3.7", "3.6")).to(be(false))
    end

    it "preserves both bounds of a comma-joined floor+cap" do
      expect(admits?(">=3.7, <3.11", "3.10")).to(be(true))
      expect(admits?(">=3.7, <3.11", "3.11")).to(be(false))
      expect(admits?(">=3.7, <3.11", "3.6")).to(be(false))
    end
  end

  describe "compatible-release operator ~= (PEP 440 semantics differ from string)" do
    # ~=3.7 means >=3.7, ==3.* i.e. >=3.7, <4
    it "translates ~=X.Y to >=X.Y, <(X+1)" do
      expect(admits?("~=3.7", "3.7")).to(be(true))
      expect(admits?("~=3.7", "3.13")).to(be(true))
      expect(admits?("~=3.7", "3.6")).to(be(false))
      expect(admits?("~=3.7", "4.0")).to(be(false))
    end

    # ~=3.7.2 means >=3.7.2, ==3.7.* i.e. >=3.7.2, <3.8
    it "translates ~=X.Y.Z to >=X.Y.Z, <X.(Y+1)" do
      expect(admits?("~=3.7.2", "3.7.4")).to(be(true))
      expect(admits?("~=3.7.2", "3.7.1")).to(be(false))
      expect(admits?("~=3.7.2", "3.8")).to(be(false))
    end
  end

  describe "prefix-match wildcards (silently missed today: Gem::Requirement raises on them)" do
    # ==3.* means >=3, <4
    it "translates ==X.* to a major-series match" do
      expect(admits?("==3.*", "3.0")).to(be(true))
      expect(admits?("==3.*", "3.13")).to(be(true))
      expect(admits?("==3.*", "2.7")).to(be(false))
      expect(admits?("==3.*", "4.0")).to(be(false))
    end

    # ==3.7.* means >=3.7, <3.8
    it "translates ==X.Y.* to a minor-series match" do
      expect(admits?("==3.7.*", "3.7.4")).to(be(true))
      expect(admits?("==3.7.*", "3.8")).to(be(false))
      expect(admits?("==3.7.*", "3.6")).to(be(false))
    end
  end

  describe "exact and arbitrary equality" do
    it "translates ==X to an exact pin" do
      expect(admits?("==3.9", "3.9")).to(be(true))
      expect(admits?("==3.9", "3.10")).to(be(false))
    end

    it "translates arbitrary equality ===X like an exact pin" do
      expect(admits?("===3.9", "3.9")).to(be(true))
      expect(admits?("===3.9", "3.10")).to(be(false))
    end
  end

  describe "!= is dropped (a hole-punch never creates a ceiling; dropping is conservative)" do
    it "drops an exclusion clause but keeps the rest of the specifier" do
      # >=3.7, !=3.9.* -> we keep >=3.7 and drop the exclusion, so 3.9 is admitted
      # (fewer findings, never a false ceiling).
      expect(admits?(">=3.7, !=3.9.*", "3.7")).to(be(true))
      expect(admits?(">=3.7, !=3.9.*", "3.9")).to(be(true))
    end

    it "yields no constraint when only exclusions are present" do
      expect(translate.call("!=3.9")).to(be_nil)
      expect(translate.call("!=3.9.*")).to(be_nil)
    end
  end

  describe "best-effort degradation (never raise, degrade to no-constraint)" do
    it "returns nil for nil / empty / whitespace input" do
      expect(translate.call(nil)).to(be_nil)
      expect(translate.call("")).to(be_nil)
      expect(translate.call("   ")).to(be_nil)
    end

    it "returns nil for a wholly unparseable specifier" do
      expect(translate.call("not a version")).to(be_nil)
    end

    it "drops an unparseable clause but keeps a usable one" do
      # A PEP 440 epoch bound Gem::Version can't parse must not sink the floor.
      expect(admits?(">=3.7, <1!3.11", "3.8")).to(be(true))
    end

    it "yields no constraint when the only clause is unparseable" do
      # `+local` / epoch versions have no RubyGems spelling; drop and degrade.
      expect(translate.call(">=3.9+local")).to(be_nil)
      expect(translate.call("<1!3.11")).to(be_nil)
    end

    it "bounds pathologically long input" do
      expect(translate.call(">=#{"9" * 500}")).to(be_nil)
    end

    it "handles a space-heavy operator/version split in linear time (no polynomial backtracking)" do
      # Exercises the previously-ambiguous `\s*(.+)` split (CodeQL ReDoS); the
      # `\s*(\S+)` form matches or fails linearly on runs of spaces.
      expect(translate.call("< #{" " * 200}x")).to(be_nil) # x is not a version -> dropped
      expect(admits?(">=#{" " * 50}3.7", "3.8")).to(be(true)) # spaces before the version are fine
    end
  end
end
