# frozen_string_literal: true

require_relative "../../lib/helpers/python_helper"

RSpec.describe(StillActive::PythonHelper) do
  let(:cycles) do
    [
      {"cycle" => "3.13", "latest" => "3.13.2", "releaseDate" => "2024-10-07", "eol" => "2029-10-31"},
      {"cycle" => "3.12", "latest" => "3.12.9", "releaseDate" => "2023-10-02", "eol" => "2028-10-31"},
      {"cycle" => "3.9", "latest" => "3.9.21", "releaseDate" => "2020-10-05", "eol" => "2025-10-31"}
    ]
  end

  before do
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(cycles))
  end

  describe ".supported_python_range" do
    it "sources the window from the python.json endoflife feed" do
      described_class.supported_python_range
      expect(StillActive::HttpHelper).to(have_received(:get_json).with(anything, "/api/python.json"))
    end

    it "reports the oldest supported cycle and latest stable (3.9 is EOL as of the fixture)" do
      range = described_class.supported_python_range
      expect(range[:oldest_supported]).to(eq(Gem::Version.new("3.12")))
      expect(range[:latest_stable]).to(eq(Gem::Version.new("3.13.2")))
    end

    it "returns nil when the feed is unavailable" do
      allow(StillActive::HttpHelper).to(receive(:get_json).and_return(nil))
      expect(described_class.supported_python_range).to(be_nil)
    end
  end
end
