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
      ))
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
  end
end
