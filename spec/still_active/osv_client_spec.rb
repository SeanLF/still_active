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
        {ecosystem: "PyPI", name: "protobuf", fixed: ["3.18.3", "4.21.6"], versioned: true}
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

  # deps.dev mirrors OSV/GHSA advisory data with an ingestion lag, so an advisory
  # AMENDED after publication (a CVE fixed on the current line, then backported, then
  # amended to carry the branch ranges) keeps being served in its pre-amendment form,
  # flagging versions the amendment has since marked patched. Receipt (2026-07-31):
  # GHSA-mh99-v99m-4gvg was published 07-24 as introduced 0 / fixed 5.0.8, amended
  # 07-31 to add the 1.1.17/2.1.3/3.0.3 branches, and deps.dev still answered from the
  # old record hours later. OSV's /v1/query reflects the amendment immediately, so it
  # settles the disagreement against deps.dev's own upstream.
  describe(".enrich version confirmation") do
    def brace_record(id)
      {
        "id" => id,
        "affected" => [
          {"package" => {"name" => "brace-expansion", "ecosystem" => "npm"},
           "ranges" => [{"type" => "SEMVER", "events" => [{"introduced" => "0"}, {"fixed" => "1.1.17"}]}]},
          {"package" => {"name" => "brace-expansion", "ecosystem" => "npm"},
           "ranges" => [{"type" => "SEMVER", "events" => [{"introduced" => "4.0.0"}, {"fixed" => "5.0.8"}]}]}
        ]
      }
    end

    def stub_query(name:, ecosystem:, version:, body:, status: 200)
      stub_request(:post, "https://api.osv.dev/v1/query")
        .with(body: {version: version, package: {name: name, ecosystem: ecosystem}}.to_json)
        .to_return(status: status, headers: {"Content-Type" => "application/json"}, body: body.is_a?(String) ? body : body.to_json)
    end

    it("drops a deps.dev advisory OSV's own version matching says does not apply") do
      stub_vuln("GHSA-mh99-v99m-4gvg", body: brace_record("GHSA-mh99-v99m-4gvg"))
      stub_query(name: "brace-expansion", ecosystem: "npm", version: "1.1.18", body: {})
      advisories = [{id: "GHSA-mh99-v99m-4gvg", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "1.1.18")

      expect(kept).to(be_empty)
    end

    it("keeps the advisory for a version OSV does list as affected") do
      stub_vuln("GHSA-mh99-v99m-4gvg", body: brace_record("GHSA-mh99-v99m-4gvg"))
      stub_query(name: "brace-expansion", ecosystem: "npm", version: "4.0.1",
        body: {vulns: [{"id" => "GHSA-mh99-v99m-4gvg"}]})
      advisories = [{id: "GHSA-mh99-v99m-4gvg", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "4.0.1")

      expect(kept.map { _1[:id] }).to(eq(["GHSA-mh99-v99m-4gvg"]))
    end

    it("matches the query result on aliases, so a CVE-keyed advisory is not dropped as absent") do
      stub_vuln("CVE-2026-14257", body: brace_record("CVE-2026-14257"))
      stub_query(name: "brace-expansion", ecosystem: "npm", version: "4.0.1",
        body: {vulns: [{"id" => "GHSA-mh99-v99m-4gvg", "aliases" => ["CVE-2026-14257"]}]})
      advisories = [{id: "CVE-2026-14257", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "4.0.1")

      expect(kept.map { _1[:id] }).to(eq(["CVE-2026-14257"]))
    end

    it("keeps the advisory when the query request fails (a transport error is not an all-clear)") do
      stub_vuln("GHSA-mh99-v99m-4gvg", body: brace_record("GHSA-mh99-v99m-4gvg"))
      stub_query(name: "brace-expansion", ecosystem: "npm", version: "1.1.18", body: {}, status: 500)
      advisories = [{id: "GHSA-mh99-v99m-4gvg", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "1.1.18")

      expect(kept.map { _1[:id] }).to(eq(["GHSA-mh99-v99m-4gvg"]))
    end

    it("keeps the advisory when OSV has no record for it (nothing to check the query against)") do
      stub_vuln("GHSA-unknown", body: {}, status: 404)
      advisories = [{id: "GHSA-unknown", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "1.1.18")

      expect(kept.map { _1[:id] }).to(eq(["GHSA-unknown"]))
    end

    it("keeps the advisory when its record does not name the package under our name (spelling mismatch)") do
      # An empty query result only means "not affected" if OSV knows the package by the
      # name we asked with. Registry name normalization differs by ecosystem (PyPI folds
      # case and -/_/.), so when the record names the package differently the empty
      # result is more likely a missed lookup than an all-clear. Fail closed.
      stub_vuln("GHSA-norm", body: {
        "id" => "GHSA-norm",
        "affected" => [{"package" => {"name" => "zope.interface", "ecosystem" => "PyPI"}, "ranges" => []}]
      })
      advisories = [{id: "GHSA-norm", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :pypi, name: "zope-interface", version: "5.0.0")

      expect(kept.map { _1[:id] }).to(eq(["GHSA-norm"]))
    end

    it("never drops a ruby-advisory-db advisory: radb matches versions itself and is the Ruby authority") do
      stub_vuln("GHSA-radb", body: {
        "id" => "GHSA-radb",
        "affected" => [{"package" => {"name" => "rack", "ecosystem" => "RubyGems"},
                        "ranges" => [{"type" => "ECOSYSTEM", "events" => [{"introduced" => "0"}, {"fixed" => "2.2.6.1"}]}]}]
      })
      stub_query(name: "rack", ecosystem: "RubyGems", version: "2.2.6.4", body: {})
      advisories = [{id: "GHSA-radb", source: "ruby-advisory-db"}, {id: "GHSA-merged", source: "merged"}]
      stub_vuln("GHSA-merged", body: {
        "id" => "GHSA-merged",
        "affected" => [{"package" => {"name" => "rack", "ecosystem" => "RubyGems"}, "ranges" => []}]
      })

      kept = described_class.enrich(advisories, ecosystem: :rubygems, name: "rack", version: "2.2.6.4")

      expect(kept.map { _1[:id] }).to(eq(["GHSA-radb", "GHSA-merged"]))
    end

    # OSV's genuine all-clear is a bare `{}`, so no 200 body carries a marker that
    # distinguishes "nothing affects this version" from "this answer is unreadable".
    # Read loosely, every one of these would fabricate an all-clear and drop a real
    # advisory; each must be treated as "we don't know" instead.
    {
      "a truncated page carrying only a next_page_token" => {"next_page_token" => "abc"},
      "a paginated page (the rest of the answer is on page 2)" => {"vulns" => [{"id" => "GHSA-other"}], "next_page_token" => "abc"},
      "an error envelope served with a 200" => {"code" => 3, "message" => "internal error"},
      "a vulns value that isn't an array" => {"vulns" => "GHSA-mh99-v99m-4gvg"},
      "a vulns object keyed by id" => {"vulns" => {"GHSA-mh99-v99m-4gvg" => {}}},
      "vulns as bare id strings" => {"vulns" => ["GHSA-mh99-v99m-4gvg"]},
      "vulns entries carrying no id" => {"vulns" => [{"summary" => "something affects you"}]},
      "vulns entries that are null" => {"vulns" => [nil, nil]},
      # The dangerous asymmetry: one readable entry beside an unreadable one. Skipping
      # the bad entry would shorten the list, and a short list reads exactly like OSV
      # never listing this advisory, so the unparseable one would be dropped.
      "a mix of readable and unreadable vulns entries" => {"vulns" => [{"id" => "GHSA-other"}, "GHSA-mh99-v99m-4gvg"]}
    }.each do |shape, body|
      it("keeps the advisory when the query answers with #{shape}") do
        stub_vuln("GHSA-mh99-v99m-4gvg", body: brace_record("GHSA-mh99-v99m-4gvg"))
        stub_query(name: "brace-expansion", ecosystem: "npm", version: "1.1.18", body: body)
        advisories = [{id: "GHSA-mh99-v99m-4gvg", source: "deps.dev"}]

        kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "1.1.18")

        expect(kept.map { _1[:id] }).to(eq(["GHSA-mh99-v99m-4gvg"]))
      end
    end

    it("treats an empty vulns list as the answer it is, the same as a bare {}") do
      stub_vuln("GHSA-mh99-v99m-4gvg", body: brace_record("GHSA-mh99-v99m-4gvg"))
      stub_query(name: "brace-expansion", ecosystem: "npm", version: "1.1.18", body: {vulns: []})
      advisories = [{id: "GHSA-mh99-v99m-4gvg", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "1.1.18")

      expect(kept).to(be_empty)
    end

    it("confirms against a record that enumerates versions instead of declaring ranges") do
      # The other route to version data: an explicit `versions` list, which /v1/query
      # matches as readily as a range. Without it this drop path has no coverage.
      stub_vuln("GHSA-enum", body: {
        "id" => "GHSA-enum",
        "affected" => [{"package" => {"name" => "brace-expansion", "ecosystem" => "npm"}, "versions" => ["1.1.16"]}]
      })
      stub_query(name: "brace-expansion", ecosystem: "npm", version: "1.1.18", body: {})
      advisories = [{id: "GHSA-enum", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "1.1.18")

      expect(kept).to(be_empty)
    end

    it("keeps the advisory when OSV's record holds no version data for the package (silence is not contradiction)") do
      # An affected entry with no ranges and no version list, or only a GIT range, means
      # OSV has no version opinion at all -- /v1/query can never return that record for
      # ANY version. Treating its empty answer as contradiction would drop the advisory
      # permanently, for every user, while deps.dev still asserts the version is affected.
      stub_vuln("GHSA-nover", body: {
        "id" => "GHSA-nover",
        "affected" => [{
          "package" => {"name" => "brace-expansion", "ecosystem" => "npm"},
          "ranges" => [{"type" => "GIT", "repo" => "https://github.com/x/y", "events" => [{"introduced" => "0"}]}]
        }]
      })
      stub_query(name: "brace-expansion", ecosystem: "npm", version: "1.1.18", body: {})
      advisories = [{id: "GHSA-nover", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "1.1.18")

      expect(kept.map { _1[:id] }).to(eq(["GHSA-nover"]))
    end

    it("matches on OSV's own id for the record, not just the id deps.dev keyed it by") do
      # Asking OSV for a CVE returns the GHSA record (it resolves aliases), so the query
      # answers with an id the deps.dev advisory never carried. Matching on deps.dev's id
      # alone would read a listed advisory as absent and drop a real finding.
      stub_vuln("CVE-2026-14257", body: brace_record("GHSA-mh99-v99m-4gvg").merge("aliases" => ["CVE-2026-14257"]))
      stub_query(name: "brace-expansion", ecosystem: "npm", version: "4.0.1",
        body: {vulns: [{"id" => "GHSA-mh99-v99m-4gvg"}]})
      advisories = [{id: "CVE-2026-14257", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "4.0.1")

      expect(kept.map { _1[:id] }).to(eq(["CVE-2026-14257"]))
    end

    it("keeps every advisory when the confirmation pass itself raises (the workflow rescue would strip the gem)") do
      stub_vuln("GHSA-mh99-v99m-4gvg", body: brace_record("GHSA-mh99-v99m-4gvg"))
      allow(StillActive::HttpHelper).to(receive(:post_json).and_raise(NoMethodError, "boom"))
      advisories = [{id: "GHSA-mh99-v99m-4gvg", source: "deps.dev"}]

      kept = nil
      expect { kept = described_class.enrich(advisories, ecosystem: :npm, name: "brace-expansion", version: "1.1.18") }
        .not_to(raise_error)
      expect(kept.map { _1[:id] }).to(eq(["GHSA-mh99-v99m-4gvg"]))
    end

    it("issues no query when no version is supplied (callers that only want enrichment)") do
      stub_vuln("GHSA-8gq9-2x98-w8hf", body: osv_record)
      advisories = [{id: "GHSA-8gq9-2x98-w8hf", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :pypi, name: "protobuf")

      expect(kept.map { _1[:id] }).to(eq(["GHSA-8gq9-2x98-w8hf"]))
      expect(a_request(:post, "https://api.osv.dev/v1/query")).not_to(have_been_made)
    end

    it("issues no query for an ecosystem OSV has no name for (cannot ask the question)") do
      stub_vuln("GHSA-x", body: {"id" => "GHSA-x", "affected" => [{"package" => {"name" => "widget", "ecosystem" => "npm"}, "ranges" => []}]})
      advisories = [{id: "GHSA-x", source: "deps.dev"}]

      kept = described_class.enrich(advisories, ecosystem: :conda, name: "widget", version: "1.0.0")

      expect(kept.map { _1[:id] }).to(eq(["GHSA-x"]))
      expect(a_request(:post, "https://api.osv.dev/v1/query")).not_to(have_been_made)
    end
  end
end
