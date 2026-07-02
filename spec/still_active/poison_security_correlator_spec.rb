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
end
