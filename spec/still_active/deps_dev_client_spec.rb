# frozen_string_literal: true

require "vcr"
require "webmock/rspec"
require_relative "../../lib/still_active/deps_dev_client"

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into(:webmock)
end

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
