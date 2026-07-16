# frozen_string_literal: true

require_relative "../../lib/helpers/ruby_helper"

RSpec.describe(StillActive::RubyHelper) do
  let(:cycles) do
    [
      {
        "cycle" => "3.4",
        "latest" => "3.4.2",
        "releaseDate" => "2024-12-25",
        "eol" => "2028-03-31",
        "lts" => false
      },
      {
        "cycle" => "3.3",
        "latest" => "3.3.7",
        "releaseDate" => "2023-12-25",
        "eol" => "2027-03-31",
        "lts" => false
      },
      {
        "cycle" => "3.2",
        "latest" => "3.2.8",
        "releaseDate" => "2022-12-25",
        "eol" => "2026-03-31",
        "lts" => false
      },
      {
        "cycle" => "3.1",
        "latest" => "3.1.6",
        "releaseDate" => "2021-12-25",
        "eol" => "2025-03-31",
        "lts" => false
      }
    ]
  end

  before do
    allow(StillActive::HttpHelper).to(receive(:get_json).and_return(cycles))
  end

  describe(".ruby_freshness") do
    before do
      allow(described_class).to(receive(:lockfile_ruby_version).and_return(nil))
    end

    context("when on latest Ruby") do
      before do
        stub_const("RUBY_VERSION", "3.4.2")
        stub_const("RUBY_ENGINE", "ruby")
      end

      it("returns version info with nil libyear") do
        result = described_class.ruby_freshness
        expect(result[:version]).to(eq("3.4.2"))
        expect(result[:latest_version]).to(eq("3.4.2"))
        expect(result[:eol]).to(be(false))
        expect(result[:libyear]).to(eq(0.0))
      end
    end

    context("when behind latest Ruby") do
      before do
        stub_const("RUBY_VERSION", "3.3.0")
        stub_const("RUBY_ENGINE", "ruby")
      end

      it("returns version delta") do
        result = described_class.ruby_freshness
        expect(result[:version]).to(eq("3.3.0"))
        expect(result[:latest_version]).to(eq("3.4.2"))
        expect(result[:libyear]).to(be > 0)
        expect(result[:eol]).to(be(false))
      end
    end

    context("when on EOL Ruby") do
      before do
        stub_const("RUBY_VERSION", "3.1.0")
        stub_const("RUBY_ENGINE", "ruby")
      end

      it("reports EOL status") do
        result = described_class.ruby_freshness
        expect(result[:version]).to(eq("3.1.0"))
        expect(result[:eol]).to(be(true))
        expect(result[:eol_date]).to(eq(Time.parse("2025-03-31")))
      end
    end

    context("when API is unavailable") do
      before do
        stub_const("RUBY_ENGINE", "ruby")
        allow(StillActive::HttpHelper).to(receive(:get_json).and_return(nil))
      end

      it("returns nil") do
        expect(described_class.ruby_freshness).to(be_nil)
      end
    end

    context("when running on JRuby with no lockfile") do
      before do
        stub_const("RUBY_ENGINE", "jruby")
      end

      it("returns nil") do
        expect(described_class.ruby_freshness).to(be_nil)
      end
    end

    context("when version is not found in cycles") do
      before do
        stub_const("RUBY_VERSION", "4.0.0")
        stub_const("RUBY_ENGINE", "ruby")
      end

      it("still returns latest info with nil dates for current cycle") do
        result = described_class.ruby_freshness
        expect(result[:version]).to(eq("4.0.0"))
        expect(result[:latest_version]).to(eq("3.4.2"))
        expect(result[:release_date]).to(be_nil)
        expect(result[:eol]).to(be_nil)
      end
    end

    context("when lockfile specifies Ruby version") do
      before do
        allow(described_class).to(receive(:lockfile_ruby_version).and_return("3.2.8"))
      end

      it("uses the lockfile version instead of RUBY_VERSION") do
        result = described_class.ruby_freshness
        expect(result[:version]).to(eq("3.2.8"))
      end
    end

    context("when lockfile specifies Ruby version on JRuby") do
      before do
        stub_const("RUBY_ENGINE", "jruby")
        allow(described_class).to(receive(:lockfile_ruby_version).and_return("3.3.0"))
      end

      it("uses the lockfile version regardless of engine") do
        result = described_class.ruby_freshness
        expect(result[:version]).to(eq("3.3.0"))
      end
    end
  end

  describe(".supported_ruby_range") do
    # eol_reached? compares each cycle's eol date against the real clock, so with
    # the fixture (3.4/3.3 future EOL, 3.2/3.1 past) the supported set is 3.3+ and
    # the newest release is 3.4.2. These runtime facts feed the per-gem ceiling.
    it("reports the oldest still-supported cycle and the latest stable release") do
      range = described_class.supported_ruby_range
      expect(range[:oldest_supported]).to(eq(Gem::Version.new("3.3")))
      expect(range[:latest_stable]).to(eq(Gem::Version.new("3.4.2")))
    end

    it("exposes normalized cycles (version, eol flag, eol date) for ceiling enrichment") do
      cycles = described_class.supported_ruby_range[:cycles]
      eol_31 = cycles.find { |c| c[:version] == Gem::Version.new("3.1") }
      expect(eol_31[:eol]).to(be(true))
      expect(eol_31[:eol_date]).to(eq(Time.parse("2025-03-31")))
      live_34 = cycles.find { |c| c[:version] == Gem::Version.new("3.4") }
      expect(live_34[:eol]).to(be(false))
    end

    it("returns nil when the endoflife API is unavailable") do
      allow(StillActive::HttpHelper).to(receive(:get_json).and_return(nil))
      expect(described_class.supported_ruby_range).to(be_nil)
    end

    it("returns nil when every known cycle is already EOL") do
      past = cycles.map { |c| c.merge("eol" => "2000-01-01") }
      allow(StillActive::HttpHelper).to(receive(:get_json).and_return(past))
      expect(described_class.supported_ruby_range).to(be_nil)
    end

    it("marks the latest stable fresh when the newest cycle shipped inside the grace window") do
      recent = cycles.map.with_index { |c, i| i.zero? ? c.merge("releaseDate" => (Time.now - (10 * 86_400)).strftime("%Y-%m-%d")) : c }
      allow(StillActive::HttpHelper).to(receive(:get_json).and_return(recent))
      expect(described_class.supported_ruby_range[:latest_stable_fresh]).to(be(true))
    end

    it("marks the latest stable not-fresh once the newest cycle is older than the grace window") do
      old = cycles.map.with_index { |c, i| i.zero? ? c.merge("releaseDate" => (Time.now - (400 * 86_400)).strftime("%Y-%m-%d")) : c }
      allow(StillActive::HttpHelper).to(receive(:get_json).and_return(old))
      expect(described_class.supported_ruby_range[:latest_stable_fresh]).to(be(false))
    end

    it("degrades freshness to false (does not raise or disable the window) on a malformed releaseDate") do
      # A malformed-but-present releaseDate must not raise out of supported_ruby_range:
      # that would null the whole range and silently disable EOL-forced criticals.
      bad = cycles.map.with_index { |c, i| i.zero? ? c.merge("releaseDate" => "2023-13-99") : c }
      allow(StillActive::HttpHelper).to(receive(:get_json).and_return(bad))
      range = nil
      expect { range = described_class.supported_ruby_range }.not_to(raise_error)
      expect(range).not_to(be_nil)
      expect(range[:latest_stable_fresh]).to(be(false))
    end

    it("keeps the window with nil latest_stable when the newest cycle's `latest` is malformed (so EOL-forced criticals still fire)") do
      # endoflife.date is best-effort third-party data; a garbled/preview `latest`
      # feeds only the latest-not-yet note, so it degrades latest_stable to nil
      # rather than nulling the whole window and silently disabling criticals.
      garbled = [cycles.first.merge("latest" => "unknown-preview"), *cycles[1..]]
      allow(StillActive::HttpHelper).to(receive(:get_json).and_return(garbled))
      range = nil
      expect { range = described_class.supported_ruby_range }.not_to(raise_error)
      expect(range).not_to(be_nil)
      expect(range[:latest_stable]).to(be_nil)
      expect(range[:oldest_supported]).to(eq(Gem::Version.new("3.3")))
    end
  end
end
