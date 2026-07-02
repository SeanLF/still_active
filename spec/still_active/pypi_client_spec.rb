# frozen_string_literal: true

require_relative "../../lib/still_active/pypi_client"

RSpec.describe(StillActive::PypiClient) do
  describe ".requires_python" do
    def stub_pypi(name, version, info)
      stub_request(:get, "https://pypi.org/pypi/#{name}/#{version}/json")
        .to_return(status: 200, body: { "info" => info }.to_json, headers: { "Content-Type" => "application/json" })
    end

    it "returns the release-level requires_python specifier" do
      stub_pypi("numba", "0.53.1", { "requires_python" => ">=3.6,<3.10" })
      expect(described_class.requires_python(name: "numba", version: "0.53.1")).to(eq(">=3.6,<3.10"))
    end

    it "returns nil when requires_python is absent from info" do
      stub_pypi("tensorflow", "2.5.0", {})
      expect(described_class.requires_python(name: "tensorflow", version: "2.5.0")).to(be_nil)
    end

    it "treats PyPI's empty-string (unset) requires_python as nil" do
      stub_pypi("tensorflow", "2.5.0", { "requires_python" => "" })
      expect(described_class.requires_python(name: "tensorflow", version: "2.5.0")).to(be_nil)
    end

    it "returns nil on a 404 (unindexed version) without raising" do
      stub_request(:get, "https://pypi.org/pypi/ghost/9.9.9/json").to_return(status: 404)
      expect(described_class.requires_python(name: "ghost", version: "9.9.9")).to(be_nil)
    end

    it "returns nil rather than raising on a non-Hash body (schema drift)" do
      stub_request(:get, "https://pypi.org/pypi/weird/1.0/json")
        .to_return(status: 200, body: [1, 2].to_json, headers: { "Content-Type" => "application/json" })
      expect(described_class.requires_python(name: "weird", version: "1.0")).to(be_nil)
    end

    it "returns nil rather than raising when `info` is a non-Hash (schema drift would make dig raise)" do
      stub_request(:get, "https://pypi.org/pypi/weird2/1.0/json")
        .to_return(status: 200, body: { "info" => "not-a-hash" }.to_json, headers: { "Content-Type" => "application/json" })
      expect { described_class.requires_python(name: "weird2", version: "1.0") }.not_to(raise_error)
      expect(described_class.requires_python(name: "weird2", version: "1.0")).to(be_nil)
    end

    it "returns nil for a nil name or version (no request made)" do
      expect(described_class.requires_python(name: nil, version: "1.0")).to(be_nil)
      expect(described_class.requires_python(name: "x", version: nil)).to(be_nil)
    end
  end
end
