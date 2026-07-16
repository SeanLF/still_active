# frozen_string_literal: true

require_relative "../../lib/helpers/summary_helper"

RSpec.describe(StillActive::SummaryHelper) do
  let(:recent) { Time.now }
  let(:ancient) { Time.now - (5 * 365 * 24 * 60 * 60) }

  def gem_data(overrides = {})
    {
      latest_version_release_date: recent,
      last_commit_date: recent,
      direct: true
    }.merge(overrides)
  end

  describe(".summarize") do
    it("counts totals, direct vs transitive, and activity levels") do
      result = {
        "fresh" => gem_data,
        "stale_transitive" => gem_data(latest_version_release_date: Time.now - (2 * 365 * 24 * 60 * 60), last_commit_date: Time.now - (2 * 365 * 24 * 60 * 60), direct: false),
        "dead" => gem_data(archived: true)
      }
      summary = described_class.summarize(result)

      expect(summary[:total_gems]).to(eq(3))
      expect(summary[:direct]).to(eq(2))
      expect(summary[:transitive]).to(eq(1))
      expect(summary[:activity].values.sum).to(eq(3))
      expect(summary[:activity][:archived]).to(eq(1))
    end

    it("always reports every activity level, even at zero") do
      summary = described_class.summarize({"fresh" => gem_data})
      expect(summary[:activity].keys).to(contain_exactly(:ok, :stale, :critical, :archived, :unknown))
      expect(summary[:activity][:critical]).to(eq(0))
    end

    it("counts archived repos, outdated gems, and vulnerabilities") do
      result = {
        "a" => gem_data(archived: true),
        "b" => gem_data(up_to_date: false),
        "c" => gem_data(vulnerability_count: 3),
        "d" => gem_data(vulnerability_count: 1)
      }
      summary = described_class.summarize(result)

      expect(summary[:archived]).to(eq(1))
      expect(summary[:outdated]).to(eq(1))
      expect(summary[:vulnerable_gems]).to(eq(2))
      expect(summary[:vulnerabilities]).to(eq(4))
    end

    it("reports ruby_eol when ruby info is given, omits it otherwise") do
      expect(described_class.summarize({}, ruby_info: {eol: true})[:ruby_eol]).to(be(true))
      expect(described_class.summarize({})).not_to(have_key(:ruby_eol))
    end

    it("handles an empty result") do
      summary = described_class.summarize({})
      expect(summary[:total_gems]).to(eq(0))
      expect(summary[:vulnerabilities]).to(eq(0))
    end
  end
end
