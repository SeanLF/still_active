# frozen_string_literal: true

RSpec.describe(StillActive::DepsDevClient) do
  describe(".version_info") do
    it("returns advisory keys and project id for a known gem") do
      VCR.use_cassette("deps_dev_version") do
        result = described_class.version_info(gem_name: "nokogiri", version: "1.19.1")

        expect(result).to(include(
          advisory_keys: an_instance_of(Array),
          project_id: "github.com/sparklemotion/nokogiri",
        ))
      end
    end

    it("returns nil when gem_name is nil") do
      expect(described_class.version_info(gem_name: nil, version: "1.0.0")).to(be_nil)
    end

    it("returns nil when version is nil") do
      expect(described_class.version_info(gem_name: "nokogiri", version: nil)).to(be_nil)
    end

    it("returns nil on timeout") do
      stub_request(:get, /api\.deps\.dev/).to_timeout

      expect(described_class.version_info(gem_name: "nokogiri", version: "1.19.1")).to(be_nil)
    end

    it("returns nil on connection refused") do
      stub_request(:get, /api\.deps\.dev/).to_raise(Errno::ECONNREFUSED)

      expect(described_class.version_info(gem_name: "nokogiri", version: "1.19.1")).to(be_nil)
    end
  end

  describe(".advisory_detail") do
    it("returns advisory details for a known advisory") do
      body = {
        "advisoryKey" => { "id" => "GHSA-test-1234" },
        "url" => "https://github.com/advisories/GHSA-test-1234",
        "title" => "Test vulnerability",
        "aliases" => [{ "id" => "CVE-2024-1234" }],
        "cvss3Score" => 9.8,
        "cvss3Vector" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      }
      stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/}).to_return(
        status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" },
      )

      result = described_class.advisory_detail(advisory_id: "GHSA-test-1234")
      expect(result).to(include(
        id: "GHSA-test-1234",
        title: "Test vulnerability",
        cvss3_score: 9.8,
        aliases: ["CVE-2024-1234"],
        source: "deps.dev",
      ))
    end

    it("drops alias entries with no id, so aliases stays a clean string array") do
      body = {
        "advisoryKey" => { "id" => "GHSA-nullalias" },
        "aliases" => [{ "id" => "CVE-2024-9" }, { "foo" => "bar" }, {}],
      }
      stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/}).to_return(
        status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" },
      )

      expect(described_class.advisory_detail(advisory_id: "GHSA-nullalias")[:aliases]).to(eq(["CVE-2024-9"]))
    end

    it("extracts cvss2_score when present") do
      body = {
        "advisoryKey" => { "id" => "GHSA-old-vuln" },
        "url" => "https://github.com/advisories/GHSA-old-vuln",
        "title" => "Old vulnerability",
        "aliases" => [],
        "cvss3Score" => nil,
        "cvss3Vector" => nil,
        "cvss2Score" => 7.5,
      }
      stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/}).to_return(
        status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" },
      )

      result = described_class.advisory_detail(advisory_id: "GHSA-old-vuln")
      expect(result).to(include(cvss3_score: nil, cvss2_score: 7.5))
    end

    it("returns nil when advisory_id is nil") do
      expect(described_class.advisory_detail(advisory_id: nil)).to(be_nil)
    end

    it("returns nil on timeout") do
      stub_request(:get, /api\.deps\.dev/).to_timeout
      expect(described_class.advisory_detail(advisory_id: "GHSA-test")).to(be_nil)
    end
  end

  describe(".project_scorecard") do
    it("returns score and date for a known project") do
      VCR.use_cassette("deps_dev_project") do
        result = described_class.project_scorecard(project_id: "github.com/sparklemotion/nokogiri")

        expect(result).to(include(
          score: a_value > 0,
          date: a_string_matching(/\d{4}-\d{2}-\d{2}/),
        ))
      end
    end

    it("returns nil when project_id is nil") do
      expect(described_class.project_scorecard(project_id: nil)).to(be_nil)
    end

    it("returns nil on timeout") do
      stub_request(:get, /api\.deps\.dev/).to_timeout

      expect(described_class.project_scorecard(project_id: "github.com/sparklemotion/nokogiri")).to(be_nil)
    end

    it("extracts the OpenSSF 'Maintained' sub-check score") do
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: {
          scorecard: {
            overallScore: 7.5,
            date: "2026-01-02",
            checks: [
              { name: "Code-Review", score: 8 },
              { name: "Maintained", score: 10 },
            ],
          },
        }.to_json,
      )

      result = described_class.project_scorecard(project_id: "github.com/some/repo")

      expect(result).to(include(score: 7.5, maintained: 10))
    end

    it("reports a nil 'Maintained' score when the check is absent") do
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: { scorecard: { overallScore: 6.0, date: "2026-01-02", checks: [] } }.to_json,
      )

      expect(described_class.project_scorecard(project_id: "github.com/some/repo")).to(include(maintained: nil))
    end

    it("degrades to a nil 'Maintained' score on a malformed checks payload (does not crash the gem)") do
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        # A non-array `checks` is a contract violation; it must not raise and
        # vanish the gem from the whole audit via the per-gem rescue.
        body: { scorecard: { overallScore: 6.0, date: "2026-01-02", checks: { "Maintained" => 10 } } }.to_json,
      )

      expect(described_class.project_scorecard(project_id: "github.com/some/repo")).to(include(maintained: nil))
    end
  end

  describe("#extract_project_id (SOURCE_REPO URL parsing)") do
    def project_id(url)
      described_class.send(:extract_project_id, { "links" => [{ "label" => "SOURCE_REPO", "url" => url }] })
    end

    it("keeps the full path for a GitLab subgroup project") do
      expect(project_id("https://gitlab.com/group/subgroup/project")).to(eq("gitlab.com/group/subgroup/project"))
    end

    it("keeps deeply nested GitLab subgroups") do
      expect(project_id("https://gitlab.com/a/b/c/project")).to(eq("gitlab.com/a/b/c/project"))
    end

    it("strips GitLab's /-/ tree suffix but keeps the subgroup path") do
      expect(project_id("https://gitlab.com/group/sub/project/-/tree/main")).to(eq("gitlab.com/group/sub/project"))
    end

    it("keeps a plain two-level GitLab project") do
      expect(project_id("https://gitlab.com/owner/project")).to(eq("gitlab.com/owner/project"))
    end

    it("keeps owner/repo for GitHub") do
      expect(project_id("https://github.com/rails/rails")).to(eq("github.com/rails/rails"))
    end

    it("strips GitHub tree/blob extras") do
      expect(project_id("https://github.com/rails/rails/tree/v7.1.0")).to(eq("github.com/rails/rails"))
    end

    it("strips a trailing slash and .git suffix") do
      expect(project_id("https://github.com/rails/rails/")).to(eq("github.com/rails/rails"))
      expect(project_id("https://github.com/rails/rails.git")).to(eq("github.com/rails/rails"))
    end

    it("returns nil when there is no SOURCE_REPO link") do
      expect(described_class.send(:extract_project_id, { "links" => [] })).to(be_nil)
    end
  end
end
