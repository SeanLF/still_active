# frozen_string_literal: true

require_relative "../../lib/still_active/poison_security_correlator"

RSpec.describe(StillActive::PoisonSecurityCorrelator) do
  describe ".correlate" do
    def vuln(cvss3)
      { id: "GHSA-x", cvss3_score: cvss3, source: "deps.dev" }
    end

    it "flags a poison cap as security-relevant when the capped dep has a HIGH advisory" do
      # The real Sentry case: archived Google libs pin a vulnerable protobuf below
      # the fix. The cap and the vuln were both computed; this connects them.
      result = {
        "pypi/google-api-core@1.0.0" => {
          ecosystem: :pypi,
          name: "google-api-core",
          constraints: [{ dependency: "protobuf", requirement: "< 5", majors_behind: 3, kind: :ceiling }],
        },
        "pypi/protobuf@4.21.6" => { ecosystem: :pypi, name: "protobuf", vulnerability_count: 1, vulnerabilities: [vuln(8.1)] },
      }
      described_class.correlate(result)
      expect(result["pypi/google-api-core@1.0.0"][:constraints].first[:capped_dep_vulnerable]).to(be(true))
      expect(result["pypi/google-api-core@1.0.0"][:poison_security_relevant]).to(be(true))
    end

    it "fails CLOSED on an unscored advisory (a confirmed advisory we can't score could be severe)" do
      result = {
        "pypi/capper@1.0.0" => { ecosystem: :pypi, name: "capper", constraints: [{ dependency: "dep", majors_behind: 3 }] },
        "pypi/dep@1.0.0" => { ecosystem: :pypi, name: "dep", vulnerability_count: 1, vulnerabilities: [vuln(nil)] },
      }
      described_class.correlate(result)
      expect(result["pypi/capper@1.0.0"][:constraints].first[:capped_dep_vulnerable]).to(be(true))
    end

    it "does NOT flag when the capped dep's only advisory is low/medium (noise, not the stuck-below-a-fix story)" do
      result = {
        "pypi/capper@1.0.0" => { ecosystem: :pypi, name: "capper", constraints: [{ dependency: "dep", majors_behind: 3 }] },
        "pypi/dep@1.0.0" => { ecosystem: :pypi, name: "dep", vulnerability_count: 1, vulnerabilities: [vuln(4.2)] },
      }
      described_class.correlate(result)
      expect(result["pypi/capper@1.0.0"][:constraints].first).not_to(have_key(:capped_dep_vulnerable))
      expect(result["pypi/capper@1.0.0"]).not_to(have_key(:poison_security_relevant))
    end

    it "does not flag a cap on a non-vulnerable dep" do
      result = {
        "pypi/foo@1.0.0" => { ecosystem: :pypi, name: "foo", constraints: [{ dependency: "bar", majors_behind: 3 }] },
        "pypi/bar@1.0.0" => { ecosystem: :pypi, name: "bar", vulnerability_count: 0 },
      }
      described_class.correlate(result)
      expect(result["pypi/foo@1.0.0"][:constraints].first).not_to(have_key(:capped_dep_vulnerable))
    end

    it "ecosystem-qualifies: a vulnerable dep in one ecosystem does not flag a same-named cap in another" do
      result = {
        "pypi/foo@1.0.0" => { ecosystem: :pypi, name: "foo", constraints: [{ dependency: "redis", majors_behind: 3 }] },
        "rubygems/redis@1.0.0" => { ecosystem: :rubygems, name: "redis", vulnerability_count: 1, vulnerabilities: [vuln(9.0)] },
      }
      described_class.correlate(result)
      expect(result["pypi/foo@1.0.0"][:constraints].first).not_to(have_key(:capped_dep_vulnerable))
    end

    it "works on the native path shape (bare-name keys, no :ecosystem)" do
      result = {
        "dormantgem" => { constraints: [{ dependency: "nokogiri", majors_behind: 2 }] },
        "nokogiri" => { vulnerability_count: 1, vulnerabilities: [vuln(7.5)] },
      }
      described_class.correlate(result)
      expect(result["dormantgem"][:constraints].first[:capped_dep_vulnerable]).to(be(true))
      expect(result["dormantgem"][:poison_security_relevant]).to(be(true))
    end
  end

  describe ".correlate below the fix" do
    # Sentry: google-api-core caps protobuf `< 5` (3 majors behind, latest ~7). Whether
    # the cap holds you BELOW THE FIX depends on where the CVE's fix lands.
    def sentry_result(fixed_versions, advisory: { id: "CVE-2026-0994", cvss3_score: 8.1 })
      {
        "pypi/google-api-core@1.0.0" => {
          ecosystem: :pypi,
          name: "google-api-core",
          constraints: [{ dependency: "protobuf", requirement: "< 5", dep_latest: "7.35.1", majors_behind: 3, kind: :ceiling }],
        },
        "pypi/protobuf@4.21.6" => {
          ecosystem: :pypi,
          name: "protobuf",
          version_used: "4.21.6",
          vulnerability_count: 1,
          vulnerabilities: [advisory.merge(fixed_versions: fixed_versions, source: "deps.dev")],
        },
      }
    end

    it "marks a cap below the fix when every fix is outside the cap (class A: unpatchable in place)" do
      result = sentry_result(["6.33.5", "5.29.6"])
      described_class.correlate(result)
      cap = result["pypi/google-api-core@1.0.0"]
      constraint = cap[:constraints].first
      expect(constraint[:capped_below_fix]).to(be(true))
      expect(constraint[:below_fix_advisory]).to(eq("CVE-2026-0994"))
      expect(constraint[:below_fix_fixed_in]).to(eq("5.29.6")) # nearest fix outside the cap
      expect(cap[:poison_below_fix]).to(be(true))
    end

    it "does NOT mark below the fix when a fix is reachable within the cap (class B: patchable in place)" do
      result = sentry_result(["4.25.8", "5.29.5"]) # 4.25.8 satisfies `< 5`
      described_class.correlate(result)
      cap = result["pypi/google-api-core@1.0.0"]
      expect(cap[:constraints].first[:capped_dep_vulnerable]).to(be(true))
      expect(cap[:constraints].first).not_to(have_key(:capped_below_fix))
      expect(cap).not_to(have_key(:poison_below_fix))
    end

    it "does NOT establish below the fix from an advisory with no known fix (class C)" do
      result = sentry_result([])
      described_class.correlate(result)
      cap = result["pypi/google-api-core@1.0.0"]
      expect(cap[:constraints].first[:capped_dep_vulnerable]).to(be(true))
      expect(cap[:constraints].first).not_to(have_key(:capped_below_fix))
    end

    it "does NOT establish below the fix from an UNSCORED advisory (no reliable fix analysis)" do
      result = sentry_result(["5.29.6"], advisory: { id: "CVE-x", cvss3_score: nil })
      described_class.correlate(result)
      cap = result["pypi/google-api-core@1.0.0"]
      expect(cap[:constraints].first[:capped_dep_vulnerable]).to(be(true)) # fail-closed still flags
      expect(cap[:constraints].first).not_to(have_key(:capped_below_fix))  # but below-fix needs a real score
    end

    it "uses the OSV label to score a CVSS-4-only advisory (deps.dev 0) for below-the-fix (the flagship)" do
      result = sentry_result(["5.29.6"], advisory: { id: "CVE-2026-0994", cvss3_score: 0, osv_severity: "HIGH" })
      described_class.correlate(result)
      expect(result["pypi/google-api-core@1.0.0"][:constraints].first[:capped_below_fix]).to(be(true))
    end

    it "ignores a downgrade fix from another release line (multi-range advisory), so a real below-the-fix cap still fires" do
      # OSV lists a fix per affected range: the used 4.21.6 is fixed by 5.29.6, but an
      # OLDER line (< 4) was fixed at 3.19.6. A downgrade to 3.19.6 does not patch
      # 4.21.6 -- it's a different, lower branch -- yet it sits within the `< 5` cap.
      # Reading it as "patchable in place" would false-negative a genuine stuck cap.
      result = sentry_result(["3.19.6", "5.29.6"])
      described_class.correlate(result)
      constraint = result["pypi/google-api-core@1.0.0"][:constraints].first
      expect(constraint[:capped_below_fix]).to(be(true))
      expect(constraint[:below_fix_fixed_in]).to(eq("5.29.6")) # the applicable fix, never the downgrade
    end

    it "names the applicable fix in the receipt, not a lower-line downgrade" do
      # Both 5.29.6 and 6.33.5 are outside the cap and above the used 4.21.6, but a
      # 3.19.6 fix for an older line must never be chosen as 'fixed in': it's below
      # the version we're on, so naming it would tell the user to downgrade.
      result = sentry_result(["3.19.6", "6.33.5", "5.29.6"])
      described_class.correlate(result)
      expect(result["pypi/google-api-core@1.0.0"][:constraints].first[:below_fix_fixed_in]).to(eq("5.29.6"))
    end

    it "names a clean fix in the receipt, never an epoch/garbage version when a parseable one exists" do
      # OSV fix strings are usually clean, but a PyPI epoch (7!2.3.4, Gem-unparseable)
      # must not be chosen as the displayed 'fixed in' over a real version. All three
      # fixes are outside the `< 5` cap (majors 7/6/5), so below-fix fires; the receipt
      # picks the lowest PARSEABLE one.
      result = sentry_result(["7!2.3.4", "6.33.5", "5.29.6"])
      described_class.correlate(result)
      expect(result["pypi/google-api-core@1.0.0"][:constraints].first[:below_fix_fixed_in]).to(eq("5.29.6"))
    end
  end
end
