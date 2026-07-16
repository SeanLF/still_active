# frozen_string_literal: true

RSpec.describe(StillActive::OsvClient) do
  # A real GHSA record shape (trimmed): a top-level GHSA severity LABEL plus per-package
  # `affected` entries whose ranges carry branch-structured `fixed` events. This is the
  # only source that gives us a real severity for a CVSS-4-only advisory (deps.dev returns
  # cvss3Score 0) AND the fixed versions the "below the fix" signal needs.
  def osv_record(severity: "HIGH", affected: nil)
    {
      "id" => "GHSA-8gq9-2x98-w8hf",
      "aliases" => ["CVE-2022-1941"],
      "severity" => [{"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
      "affected" => affected || [
        {
          "package" => {"name" => "protobuf", "ecosystem" => "PyPI"},
          "ranges" => [
            {"type" => "ECOSYSTEM", "events" => [{"introduced" => "0"}, {"fixed" => "3.18.3"}]},
            {"type" => "ECOSYSTEM", "events" => [{"introduced" => "4.0.0"}, {"fixed" => "4.21.6"}]}
          ]
        }
      ]
    }.tap { |r| r["database_specific"] = {"severity" => severity} if severity }
  end

  def stub_vuln(id, body:, status: 200)
    stub_request(:get, "https://api.osv.dev/v1/vulns/#{id}")
      .to_return(status: status, headers: {"Content-Type" => "application/json"}, body: body.is_a?(String) ? body : body.to_json)
  end

  describe(".detail") do
    it("returns the GHSA severity label and the affected packages with their fixed versions") do
      stub_vuln("GHSA-8gq9-2x98-w8hf", body: osv_record)

      detail = described_class.detail(advisory_id: "GHSA-8gq9-2x98-w8hf")

      expect(detail[:severity_label]).to(eq("HIGH"))
      expect(detail[:affected]).to(contain_exactly(
        {ecosystem: "PyPI", name: "protobuf", fixed: ["3.18.3", "4.21.6"]}
      ))
    end

    it("returns nil when the advisory id is nil (nothing to enrich)") do
      expect(described_class.detail(advisory_id: nil)).to(be_nil)
    end

    it("returns nil on a 404 so a missing OSV record degrades to no enrichment") do
      stub_vuln("GHSA-missing", body: {}, status: 404)
      expect(described_class.detail(advisory_id: "GHSA-missing")).to(be_nil)
    end

    it("leaves severity_label nil when the record carries no GHSA severity label") do
      stub_vuln("GHSA-nolabel", body: osv_record(severity: nil))
      expect(described_class.detail(advisory_id: "GHSA-nolabel")[:severity_label]).to(be_nil)
    end

    it("hands the highest-priority vector to the scorer, preferring v4 (the version deps.dev can't score)") do
      v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      record = osv_record.merge("severity" => [
        {"type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
        {"type" => "CVSS_V4", "score" => v4_vector}
      ])
      stub_vuln("GHSA-cvss", body: record)
      # cvss-suite is an optional dependency (CvssHelper.score), so here we assert
      # OsvClient hands the V4 vector (not the v3) to the scorer and surfaces the
      # result -- the .with guard fails if it picked v3. The math is CvssHelper's own.
      allow(StillActive::CvssHelper).to(receive(:score).with(v4_vector).and_return(9.3))

      detail = described_class.detail(advisory_id: "GHSA-cvss")

      expect(detail[:cvss_score]).to(eq(9.3))
      expect(detail[:cvss_version]).to(eq("4.0"))
    end

    it("leaves the cvss score nil when the record carries no usable vector") do
      stub_vuln("GHSA-novec", body: osv_record.merge("severity" => []))
      expect(described_class.detail(advisory_id: "GHSA-novec")[:cvss_score]).to(be_nil)
    end

    it("labels a CVSS v2-only vector via the entry type (v2 vectors carry no CVSS: prefix)") do
      stub_vuln("GHSA-v2", body: osv_record.merge("severity" => [{"type" => "CVSS_V2", "score" => "AV:N/AC:L/Au:N/C:P/I:P/A:P"}]))
      expect(described_class.detail(advisory_id: "GHSA-v2")[:cvss_version]).to(eq("2.0"))
    end

    it("yields no fixed versions for a versions-only advisory (enumerated, no fix boundary)") do
      record = osv_record(affected: [{
        "package" => {"name" => "protobuf", "ecosystem" => "PyPI"},
        "versions" => ["4.21.0", "4.21.5"]
      }])
      stub_vuln("GHSA-versonly", body: record)
      expect(described_class.detail(advisory_id: "GHSA-versonly")[:affected].first[:fixed]).to(eq([]))
    end

    it("returns nil for a non-object body (a CDN/error envelope that parses to an array)") do
      # HttpHelper hands back whatever parses; a JSON array/scalar must not raise on dig.
      stub_vuln("GHSA-array", body: "[]")
      expect(described_class.detail(advisory_id: "GHSA-array")).to(be_nil)
    end

    it("skips malformed affected/ranges/events entries without raising, keeping the good fixes beside them") do
      # A null in affected, an object where an array belongs, and a null in ranges/events
      # are all valid JSON that HttpHelper returns intact -- they must degrade, not crash.
      record = osv_record(affected: [
        nil,
        {"package" => {"name" => "protobuf", "ecosystem" => "PyPI"}, "ranges" => "not-an-array"},
        {
          "package" => {"name" => "protobuf", "ecosystem" => "PyPI"},
          "ranges" => [nil, {"events" => [nil, {"fixed" => "4.21.6"}]}]
        }
      ])
      stub_vuln("GHSA-messy", body: record)

      detail = described_class.detail(advisory_id: "GHSA-messy")

      expect(detail[:severity_label]).to(eq("HIGH"))
      expect(detail[:affected].map { |a| a[:fixed] }).to(eq([[], ["4.21.6"]]))
    end
  end

  describe(".enrich") do
    it("attaches the OSV label and the package's fixed versions to each advisory in place") do
      stub_vuln("GHSA-8gq9-2x98-w8hf", body: osv_record)
      advisories = [{id: "GHSA-8gq9-2x98-w8hf", source: "deps.dev", cvss3_score: 0}]

      described_class.enrich(advisories, ecosystem: :pypi, name: "protobuf")

      expect(advisories.first).to(include(osv_severity: "HIGH", fixed_versions: ["3.18.3", "4.21.6"]))
    end

    it("attaches the scorer's v4 number, giving a CVSS-4-only advisory (deps.dev 0) a real score") do
      v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
      record = osv_record.merge("severity" => [{"type" => "CVSS_V4", "score" => v4_vector}])
      stub_vuln("GHSA-8gq9-2x98-w8hf", body: record)
      advisories = [{id: "GHSA-8gq9-2x98-w8hf", cvss3_score: 0}] # deps.dev's v4-only sentinel
      # With the optional scorer present, the v4 vector's number fills deps.dev's gap.
      allow(StillActive::CvssHelper).to(receive(:score).with(v4_vector).and_return(9.3))

      described_class.enrich(advisories, ecosystem: :pypi, name: "protobuf")

      expect(advisories.first).to(include(osv_cvss_score: 9.3, cvss_version: "4.0"))
      expect(StillActive::VulnerabilityHelper.effective_score(advisories.first)).to(eq(9.3))
    end

    it("maps our ecosystem symbols to OSV's casing when filtering affected packages") do
      # rubygems -> "RubyGems"; only the matching package's fixes are attached.
      record = osv_record(affected: [
        {
          "package" => {"name" => "rack", "ecosystem" => "RubyGems"},
          "ranges" => [{"type" => "ECOSYSTEM", "events" => [{"introduced" => "0"}, {"fixed" => "2.2.6.1"}]}]
        },
        {"package" => {"name" => "rack", "ecosystem" => "PyPI"}, "ranges" => []}
      ])
      stub_vuln("GHSA-rack", body: record)
      advisories = [{id: "GHSA-rack"}]

      described_class.enrich(advisories, ecosystem: :rubygems, name: "rack")

      expect(advisories.first[:fixed_versions]).to(eq(["2.2.6.1"]))
    end

    it("maps every ecosystem still_active resolves to OSV's casing (maven/go/nuget too, for fix-data parity)") do
      # deps.dev/SbomReader resolve 7 systems; OSV names three of them Maven/Go/NuGet.
      # Without these, fix-version filtering for those ecosystems falls back to loose
      # name-only matching. Verified casing against live OSV records.
      {
        maven: "Maven", go: "Go", nuget: "NuGet"
      }.each do |eco, osv_name|
        record = osv_record(affected: [
          {
            "package" => {"name" => "widget", "ecosystem" => osv_name},
            "ranges" => [{"type" => "ECOSYSTEM", "events" => [{"introduced" => "0"}, {"fixed" => "1.2.3"}]}]
          },
          {"package" => {"name" => "widget", "ecosystem" => "PyPI"}, "ranges" => []}
        ])
        stub_vuln("GHSA-#{eco}", body: record)
        advisories = [{id: "GHSA-#{eco}"}]

        described_class.enrich(advisories, ecosystem: eco, name: "widget")

        expect(advisories.first[:fixed_versions]).to(eq(["1.2.3"]))
      end
    end

    it("treats a nil ecosystem as rubygems (the native path carries no ecosystem)") do
      record = osv_record(affected: [
        {
          "package" => {"name" => "rack", "ecosystem" => "RubyGems"},
          "ranges" => [{"type" => "ECOSYSTEM", "events" => [{"introduced" => "0"}, {"fixed" => "2.2.6.1"}]}]
        }
      ])
      stub_vuln("GHSA-rack", body: record)
      advisories = [{id: "GHSA-rack"}]

      described_class.enrich(advisories, ecosystem: nil, name: "rack")

      expect(advisories.first[:fixed_versions]).to(eq(["2.2.6.1"]))
    end

    it("leaves an advisory untouched when OSV has no record for it (best-effort enrichment)") do
      stub_vuln("GHSA-missing", body: {}, status: 404)
      advisories = [{id: "GHSA-missing", source: "deps.dev"}]

      described_class.enrich(advisories, ecosystem: :pypi, name: "protobuf")

      expect(advisories.first).to(eq({id: "GHSA-missing", source: "deps.dev"}))
    end

    it("never lets an unexpected error escape enrich (the workflow's rescue would drop the whole gem)") do
      # Defense in depth beyond the shape guards: even a surprise raise must leave the
      # advisory as deps.dev produced it, not vanish a known-vulnerable dependency.
      allow(described_class).to(receive(:detail).and_raise(TypeError, "boom"))
      advisories = [{id: "GHSA-x", source: "deps.dev"}]

      expect { described_class.enrich(advisories, ecosystem: :pypi, name: "protobuf") }.not_to(raise_error)
      expect(advisories.first).to(eq({id: "GHSA-x", source: "deps.dev"}))
    end
  end
end
