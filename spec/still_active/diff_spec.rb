# frozen_string_literal: true

require "json"
require_relative "../../lib/still_active/diff"

RSpec.describe(StillActive::Diff) do
  let(:baseline) { JSON.parse(File.read(File.expand_path("../fixtures/diff/baseline.json", __dir__))) }
  let(:current) { JSON.parse(File.read(File.expand_path("../fixtures/diff/current.json", __dir__))) }

  describe(".call") do
    subject(:diff) { described_class.call(baseline: baseline, current: current) }

    describe("schema validation") do
      it("rejects baseline with unsupported schema_version") do
        future = baseline.merge("schema_version" => 999)
        expect { described_class.call(baseline: future, current: current) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError, /schema_version/))
      end

      it("rejects current with unsupported schema_version") do
        future = current.merge("schema_version" => 999)
        expect { described_class.call(baseline: baseline, current: future) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError, /schema_version/))
      end

      it("rejects a baseline that is valid JSON but not an object (e.g. a top-level array)") do
        # A user can mis-point --baseline at any JSON file; it must fail the
        # clean error path, not crash with TypeError on snapshot["schema_version"].
        expect { described_class.call(baseline: [], current: current) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError))
      end

      it("rejects a baseline whose gems section is not an object") do
        malformed = { "schema_version" => 1, "gems" => [] }
        expect { described_class.call(baseline: malformed, current: current) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError, /gems/))
      end

      it("rejects a baseline whose gem value is not an object, instead of crashing or silently mis-diffing") do
        # "rails" is in both snapshots, so a null/scalar value here would reach
        # the intersection branch: a nil crashes (before["version_used"]), a
        # string silently produces a wrong diff. Both must be a clean rejection.
        malformed = { "schema_version" => 1, "gems" => { "rails" => nil } }
        expect { described_class.call(baseline: malformed, current: current) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError, /rails/))
      end

      it("rejects a non-numeric numeric field instead of silently fabricating a count") do
        # vuln_count does .to_i, so "two" would silently become 0 and feed a
        # bogus vulnerability regression. Reject rather than fabricate.
        malformed = { "schema_version" => 1, "gems" => { "rails" => { "vulnerability_count" => "two" } } }
        expect { described_class.call(baseline: malformed, current: current) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError, /rails/))
      end

      it("rejects a vulnerabilities field that is not an array instead of silently dropping advisory ids") do
        malformed = { "schema_version" => 1, "gems" => { "rails" => { "vulnerabilities" => "lots" } } }
        expect { described_class.call(baseline: malformed, current: current) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError, /rails/))
      end

      it("rejects a ruby section that is not an object instead of crashing or silently ignoring it") do
        malformed = { "schema_version" => 1, "gems" => {}, "ruby" => ["3.2.0"] }
        expect { described_class.call(baseline: malformed, current: current) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError, /ruby/))
      end

      it("rejects a non-object vulnerability entry, which advisory_ids would deref as a hash") do
        malformed = { "schema_version" => 1, "gems" => { "rails" => { "vulnerabilities" => [42] } } }
        expect { described_class.call(baseline: malformed, current: current) }
          .to(raise_error(StillActive::Diff::UnsupportedSchemaError, /rails/))
      end
    end

    describe("added gems") do
      it("identifies gems present in current but not baseline") do
        expect(diff.added.map(&:name)).to(eq(["newly_added"]))
      end
    end

    describe("removed gems") do
      it("identifies gems present in baseline but not current") do
        expect(diff.removed.map(&:name)).to(eq(["to_be_removed"]))
      end
    end

    describe("version bumps") do
      it("identifies gems with changed version_used") do
        bump = diff.bumped.find { |b| b.name == "rails" }
        expect(bump.before_version).to(eq("7.0.0"))
        expect(bump.after_version).to(eq("7.1.0"))
      end

      it("classifies a bump that closed vulns as :closed_vulns") do
        bump = diff.bumped.find { |b| b.name == "rails" }
        expect(bump.kind).to(eq(:closed_vulns))
      end
    end

    describe("regressions") do
      it("flags newly-archived added gems") do
        regs = diff.regressions.select { |r| r.kind == :new_gem_archived }
        expect(regs.map(&:gem)).to(eq(["newly_added"]))
      end

      it("does NOT flag libyear-to-latest worsening when version moved forward") do
        # rails: baseline libyear 1.0, current 0.7 — moved forward, so no regression.
        # Even if libyear had grown (e.g. upstream released faster), moving forward
        # shouldn't be a regression on THIS PR.
        libyear_regs = diff.regressions.select { |r| r.kind == :libyear_worsened }
        expect(libyear_regs).to(be_empty)
      end

      it("flags libyear growth on an UNCHANGED pinned version") do
        baseline_v2 = baseline.merge(
          "gems" => baseline["gems"].merge(
            "stagnant" => { "source_type" => "rubygems", "version_used" => "1.0.0", "libyear" => 0.5 },
          ),
        )
        current_v2 = current.merge(
          "gems" => current["gems"].merge(
            "stagnant" => { "source_type" => "rubygems", "version_used" => "1.0.0", "libyear" => 1.2 },
          ),
        )
        d = described_class.call(baseline: baseline_v2, current: current_v2)
        regs = d.regressions.select { |r| r.gem == "stagnant" && r.kind == :libyear_worsened }
        expect(regs.size).to(eq(1))
      end

      it("flags Scorecard drops of >= 1.0") do
        regs = diff.regressions.select { |r| r.kind == :scorecard_dropped }
        expect(regs.map(&:gem)).to(include("scorecard_dropping"))
      end

      it("ignores Scorecard drops below 1.0") do
        # untouched: scorecard unchanged at 8.0 — no regression.
        regs = diff.regressions.select { |r| r.kind == :scorecard_dropped && r.gem == "untouched" }
        expect(regs).to(be_empty)
      end

      it("emits no regression for the bump that closed vulns") do
        regs = diff.regressions.select { |r| r.gem == "rails" }
        expect(regs).to(be_empty)
      end
    end

    describe("ruby delta") do
      it("reports unchanged ruby version") do
        expect(diff.ruby[:version_changed]).to(be(false))
        expect(diff.ruby[:newly_eol]).to(be(false))
      end

      it("flags ruby going EOL on this PR") do
        baseline_v2 = baseline.merge("ruby" => baseline["ruby"].merge("eol" => false))
        current_v2 = current.merge("ruby" => current["ruby"].merge("eol" => true, "version" => "2.7.8"))
        d = described_class.call(baseline: baseline_v2, current: current_v2)
        expect(d.ruby[:newly_eol]).to(be(true))
        expect(d.regressions.any? { |r| r.kind == :ruby_eol_introduced }).to(be(true))
      end
    end

    describe("scorecard threshold crossing") do
      it("flags a crossing of 7.0 even when the absolute drop is <1.0") do
        baseline_v2 = baseline.merge(
          "gems" => baseline["gems"].merge(
            "edge" => { "source_type" => "rubygems", "version_used" => "1.0.0", "scorecard_score" => 7.2 },
          ),
        )
        current_v2 = current.merge(
          "gems" => current["gems"].merge(
            "edge" => { "source_type" => "rubygems", "version_used" => "1.0.0", "scorecard_score" => 6.5 },
          ),
        )
        d = described_class.call(baseline: baseline_v2, current: current_v2)
        regs = d.regressions.select { |r| r.gem == "edge" && r.kind == :scorecard_dropped }
        expect(regs.size).to(eq(1))
      end
    end

    describe("vulnerability detection") do
      it("flags a bump that introduced new vulns") do
        baseline_v2 = baseline.merge(
          "gems" => baseline["gems"].merge(
            "rails" => baseline["gems"]["rails"].merge("vulnerability_count" => 0, "vulnerabilities" => []),
          ),
        )
        current_v2 = current.merge(
          "gems" => current["gems"].merge(
            "rails" => current["gems"]["rails"].merge(
              "version_used" => "7.1.0",
              "vulnerability_count" => 1,
              "vulnerabilities" => [{ "id" => "CVE-new-1", "cvss3_score" => 9.0 }],
            ),
          ),
        )
        d = described_class.call(baseline: baseline_v2, current: current_v2)
        regs = d.regressions.select { |r| r.gem == "rails" }
        expect(regs.any? { |r| r.kind == :bump_introduced_vulns }).to(be(true))
      end

      it("flags a new vulnerability on an unchanged version") do
        baseline_v2 = baseline.merge(
          "gems" => baseline["gems"].merge(
            "untouched" => baseline["gems"]["untouched"].merge(
              "vulnerability_count" => 0,
              "vulnerabilities" => [],
            ),
          ),
        )
        current_v2 = current.merge(
          "gems" => current["gems"].merge(
            "untouched" => current["gems"]["untouched"].merge(
              "vulnerability_count" => 1,
              "vulnerabilities" => [{ "id" => "CVE-new-2", "cvss3_score" => 7.0 }],
            ),
          ),
        )
        d = described_class.call(baseline: baseline_v2, current: current_v2)
        regs = d.regressions.select { |r| r.gem == "untouched" && r.kind == :new_vulnerability }
        expect(regs.size).to(eq(1))
      end
    end

    describe("yanked detection") do
      it("flags a version that became yanked since baseline") do
        baseline_v2 = baseline.merge(
          "gems" => baseline["gems"].merge(
            "yanker" => { "source_type" => "rubygems", "version_used" => "1.0.0", "version_yanked" => false },
          ),
        )
        current_v2 = current.merge(
          "gems" => current["gems"].merge(
            "yanker" => { "source_type" => "rubygems", "version_used" => "1.0.0", "version_yanked" => true },
          ),
        )
        d = described_class.call(baseline: baseline_v2, current: current_v2)
        regs = d.regressions.select { |r| r.gem == "yanker" && r.kind == :version_yanked }
        expect(regs.size).to(eq(1))
      end
    end
  end
end
