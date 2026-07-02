# frozen_string_literal: true

require_relative "../../lib/helpers/endoflife_helper"

RSpec.describe(StillActive::EndoflifeHelper) do
  # The ecosystem-neutral support-window builder over an endoflife.date feed.
  # RubyHelper and PythonHelper both delegate here; the only difference between
  # them is the feed path. Fixtures mirror the ruby.json / python.json shape.
  let(:cycles) do
    [
      { "cycle" => "3.13", "latest" => "3.13.2", "releaseDate" => "2024-10-07", "eol" => "2029-10-31" },
      { "cycle" => "3.12", "latest" => "3.12.9", "releaseDate" => "2023-10-02", "eol" => "2028-10-31" },
      { "cycle" => "3.9", "latest" => "3.9.21", "releaseDate" => "2020-10-05", "eol" => "2025-10-31" },
      { "cycle" => "3.8", "latest" => "3.8.20", "releaseDate" => "2019-10-14", "eol" => "2024-10-14" },
    ]
  end

  before do
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(cycles))
  end

  def window
    described_class.support_window(feed_path: "/api/python.json")
  end

  it "fetches the given feed path" do
    window
    expect(StillActive::HttpHelper).to(have_received(:get_json).with(anything, "/api/python.json"))
  end

  it "reports the oldest still-supported cycle and the latest stable release" do
    # 3.13/3.12 future EOL, 3.9/3.8 past -> supported floor 3.12, newest 3.13.2.
    expect(window[:oldest_supported]).to(eq(Gem::Version.new("3.12")))
    expect(window[:latest_stable]).to(eq(Gem::Version.new("3.13.2")))
  end

  it "exposes normalized cycles (version, eol flag, eol date)" do
    eol_38 = window[:cycles].find { |c| c[:version] == Gem::Version.new("3.8") }
    expect(eol_38[:eol]).to(be(true))
    expect(eol_38[:eol_date]).to(eq(Time.parse("2024-10-14")))
    live = window[:cycles].find { |c| c[:version] == Gem::Version.new("3.13") }
    expect(live[:eol]).to(be(false))
  end

  it "returns nil when the endoflife feed is unavailable" do
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(nil))
    expect(window).to(be_nil)
  end

  it "returns nil when the feed is empty" do
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return([]))
    expect(window).to(be_nil)
  end

  it "returns nil when every known cycle is already EOL" do
    past = cycles.map { |c| c.merge("eol" => "2000-01-01") }
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(past))
    expect(window).to(be_nil)
  end

  it "skips a cycle whose version is malformed rather than crashing" do
    garbled_cycle = cycles + [{ "cycle" => "not-a-version", "latest" => "9.9", "eol" => "2029-01-01" }]
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(garbled_cycle))
    expect { window }.not_to(raise_error)
    expect(window[:cycles].map { |c| c[:version] }).not_to(include(nil))
  end

  it "marks the latest stable fresh inside the grace window" do
    recent = cycles.map.with_index { |c, i| i.zero? ? c.merge("releaseDate" => (Time.now - (10 * 86_400)).strftime("%Y-%m-%d")) : c }
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(recent))
    expect(window[:latest_stable_fresh]).to(be(true))
  end

  it "marks the latest stable not-fresh past the grace window" do
    old = cycles.map.with_index { |c, i| i.zero? ? c.merge("releaseDate" => (Time.now - (400 * 86_400)).strftime("%Y-%m-%d")) : c }
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(old))
    expect(window[:latest_stable_fresh]).to(be(false))
  end

  it "degrades freshness to false (never raises, never nulls the window) on a malformed releaseDate" do
    bad = cycles.map.with_index { |c, i| i.zero? ? c.merge("releaseDate" => "2023-13-99") : c }
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(bad))
    range = nil
    expect { range = window }.not_to(raise_error)
    expect(range).not_to(be_nil)
    expect(range[:latest_stable_fresh]).to(be(false))
  end

  it "keeps the window with nil latest_stable when the newest cycle's `latest` is malformed (criticals depend only on the eol flags, so they must still fire)" do
    garbled = [cycles.first.merge("latest" => "unknown-preview"), *cycles[1..]]
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(garbled))
    expect { window }.not_to(raise_error)
    expect(window).not_to(be_nil)
    expect(window[:latest_stable]).to(be_nil)
    expect(window[:latest_stable_fresh]).to(be(false))
    expect(window[:oldest_supported]).to(eq(Gem::Version.new("3.12")))
  end

  it "degrades a single cycle's malformed eol to non-EOL rather than raising and nulling the whole window" do
    # A garbled eol on one cycle must cost at most that cycle, never disable the
    # signal tree-wide (which would hide EOL-forced criticals).
    bad = cycles.map { |c| c["cycle"] == "3.9" ? c.merge("eol" => "2024-13-99") : c }
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(bad))
    expect { window }.not_to(raise_error)
    expect(window).not_to(be_nil)
    cycle_39 = window[:cycles].find { |c| c[:version] == Gem::Version.new("3.9") }
    expect(cycle_39[:eol]).to(be(false))
  end

  describe ".parse_date" do
    it "returns nil for a malformed date rather than raising" do
      expect { described_class.parse_date("2024-13-99") }.not_to(raise_error)
      expect(described_class.parse_date("2024-13-99")).to(be_nil)
      expect(described_class.parse_date(nil)).to(be_nil)
    end
  end

  describe ".eol_reached?" do
    it "returns nil for a malformed eol string rather than raising" do
      expect(described_class.eol_reached?("nonsense")).to(be_nil)
    end

    it "returns true/false for valid past/future eol dates and passes booleans through" do
      expect(described_class.eol_reached?("2000-01-01")).to(be(true))
      expect(described_class.eol_reached?("2999-01-01")).to(be(false))
      expect(described_class.eol_reached?(true)).to(be(true))
      expect(described_class.eol_reached?(false)).to(be(false))
    end
  end
end
