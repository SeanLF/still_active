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
        "lts" => false,
      },
      {
        "cycle" => "3.3",
        "latest" => "3.3.7",
        "releaseDate" => "2023-12-25",
        "eol" => "2027-03-31",
        "lts" => false,
      },
      {
        "cycle" => "3.2",
        "latest" => "3.2.8",
        "releaseDate" => "2022-12-25",
        "eol" => "2026-03-31",
        "lts" => false,
      },
      {
        "cycle" => "3.1",
        "latest" => "3.1.6",
        "releaseDate" => "2021-12-25",
        "eol" => "2025-03-31",
        "lts" => false,
      },
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
end
