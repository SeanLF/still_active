# frozen_string_literal: true

require "bundler/audit"
require "bundler/audit/database"

RSpec.describe(StillActive::RubyAdvisoryDb) do
  # A stand-in for a bundler-audit Advisory: the CVSS scores live in #to_h,
  # while ids are exposed as methods (matches bundler-audit 0.9.3).
  def fake_advisory(ghsa_id:, cve_id:, id:, identifiers:, to_h:, patched_versions: [Gem::Requirement.new(">= 1.0")], unaffected_versions: [])
    instance_double(
      Bundler::Audit::Advisory,
      ghsa_id: ghsa_id,
      cve_id: cve_id,
      id: id,
      identifiers: identifiers,
      to_h: to_h,
      patched_versions: patched_versions,
      unaffected_versions: unaffected_versions,
    )
  end

  describe(".to_vulnerability") do
    subject(:vulnerability) { described_class.to_vulnerability(advisory) }

    let(:advisory) do
      fake_advisory(
        ghsa_id: "GHSA-5r2p-j47h-mhpg",
        cve_id: "CVE-2018-16471",
        id: "CVE-2018-16471",
        identifiers: ["CVE-2018-16471", "GHSA-5r2p-j47h-mhpg"],
        to_h: {
          cvss_v3: 6.1,
          cvss_v2: nil,
          title: "Possible XSS vulnerability in Rack",
          url: "https://groups.google.com/forum/#!topic/ruby-security-ann/x",
        },
      )
    end

    it("prefers the GHSA id as the primary identifier") do
      expect(vulnerability[:id]).to(eq("GHSA-5r2p-j47h-mhpg"))
    end

    it("lists the remaining identifiers as aliases") do
      expect(vulnerability[:aliases]).to(contain_exactly("CVE-2018-16471"))
    end

    it("reads the CVSS scores from to_h") do
      expect(vulnerability).to(include(cvss3_score: 6.1, cvss2_score: nil))
    end

    it("has no CVSS vector (bundler-audit does not expose one)") do
      expect(vulnerability[:cvss3_vector]).to(be_nil)
    end

    it("carries title and url from to_h") do
      expect(vulnerability).to(include(
        title: "Possible XSS vulnerability in Rack",
        url: "https://groups.google.com/forum/#!topic/ruby-security-ann/x",
      ))
    end

    it("tags the source as ruby-advisory-db") do
      expect(vulnerability[:source]).to(eq("ruby-advisory-db"))
    end

    def unpatched(unaffected: [])
      fake_advisory(
        ghsa_id: "GHSA-x",
        cve_id: "CVE-x",
        id: "CVE-x",
        identifiers: ["CVE-x"],
        to_h: {},
        patched_versions: [],
        unaffected_versions: unaffected,
      )
    end

    it("marks no_fix_available when the advisory declares no patched or forward-safe version") do
      expect(described_class.to_vulnerability(unpatched)[:no_fix_available]).to(be(true))
    end

    it("marks no_fix_available when the only safe versions are older than the flaw (< X)") do
      advisory = unpatched(unaffected: [Gem::Requirement.new("< 1.0.6")])
      expect(described_class.to_vulnerability(advisory)[:no_fix_available]).to(be(true))
    end

    it("does NOT mark no_fix when a later clean release exists in unaffected_versions (backdoor/yank pattern)") do
      # CVE-2019-15224 shape: version X was backdoored, "> X" is a clean forward fix
      # recorded in unaffected_versions rather than patched_versions.
      advisory = unpatched(unaffected: [Gem::Requirement.new("< 1.18.0"), Gem::Requirement.new("> 1.18.0")])
      expect(described_class.to_vulnerability(advisory)[:no_fix_available]).to(be(false))
    end

    it("marks no_fix_available false when a patched version exists") do
      expect(vulnerability[:no_fix_available]).to(be(false))
    end

    it("falls back to the CVE id when there is no GHSA id") do
      advisory = fake_advisory(
        ghsa_id: nil,
        cve_id: "CVE-2011-0001",
        id: "OSVDB-1",
        identifiers: ["CVE-2011-0001"],
        to_h: { cvss_v3: nil, cvss_v2: 5.0 },
      )
      expect(described_class.to_vulnerability(advisory)[:id]).to(eq("CVE-2011-0001"))
    end
  end

  describe(".advisories_for") do
    let(:advisory) do
      fake_advisory(
        ghsa_id: "GHSA-xxx",
        cve_id: "CVE-9",
        id: "CVE-9",
        identifiers: ["CVE-9", "GHSA-xxx"],
        to_h: { cvss_v3: 7.5, cvss_v2: nil },
      )
    end

    it("returns an empty array when the database is unavailable") do
      expect(described_class.advisories_for(database: nil, gem_name: "rack", version: "2.0.0")).to(eq([]))
    end

    it("maps each advisory the database yields for the gem") do
      database = instance_double(Bundler::Audit::Database)
      allow(database).to(receive(:check_gem).and_yield(advisory))

      result = described_class.advisories_for(database: database, gem_name: "rack", version: "2.0.0")

      expect(result.length).to(eq(1))
      expect(result.first).to(include(id: "GHSA-xxx", source: "ruby-advisory-db"))
    end

    it("returns an empty array (not a raise) for an unparseable version") do
      database = instance_double(Bundler::Audit::Database)
      expect(described_class.advisories_for(database: database, gem_name: "rack", version: "not-a-version")).to(eq([]))
    end

    it("warns and returns [] when the checkout has a malformed advisory, rather than silently hiding it") do
      database = instance_double(Bundler::Audit::Database)
      allow(database).to(receive(:check_gem).and_raise(Gem::Requirement::BadRequirementError.new("bad")))

      expect do
        result = described_class.advisories_for(database: database, gem_name: "rack", version: "2.0.0")
        expect(result).to(eq([]))
      end.to(output(/malformed advisory for rack.*bundle audit update/).to_stderr)
    end
  end

  describe(".load") do
    it("returns nil when the advisory database directory is absent") do
      allow(Bundler::Audit::Database).to(receive(:new).and_raise(ArgumentError, "not a directory"))
      expect(described_class.load).to(be_nil)
    end

    it("returns the database when it is present") do
      database = instance_double(Bundler::Audit::Database, last_updated_at: Time.now)
      allow(Bundler::Audit::Database).to(receive(:new).and_return(database))
      expect(described_class.load).to(eq(database))
    end
  end
end
