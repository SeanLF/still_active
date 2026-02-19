# frozen_string_literal: true

require_relative "../../lib/helpers/health_score_helper"
require_relative "../../lib/still_active/core_ext"

using StillActive::CoreExt

RSpec.describe(StillActive::HealthScoreHelper) do
  before { StillActive.reset }

  def gem_data(libyear: 0.0, yanked: false, archived: false, last_commit: Time.now, scorecard: 10.0, vuln_count: 0)
    {
      libyear: libyear,
      version_yanked: yanked,
      archived: archived,
      last_commit_date: last_commit,
      latest_version_release_date: Time.now,
      latest_pre_release_version_release_date: nil,
      scorecard_score: scorecard,
      vulnerability_count: vuln_count,
    }
  end

  describe(".gem_score") do
    it("returns 100 for a perfect gem") do
      expect(described_class.gem_score(gem_data)).to(eq(100))
    end

    it("returns 0 for an archived gem with vulnerabilities") do
      data = gem_data(archived: true, vuln_count: 5, libyear: 5.0, scorecard: 0)
      expect(described_class.gem_score(data)).to(eq(0))
    end

    it("penalizes yanked versions") do
      data = gem_data(yanked: true)
      score = described_class.gem_score(data)
      expect(score).to(be < 100)
    end

    it("penalizes high libyear") do
      data = gem_data(libyear: 3.0)
      score = described_class.gem_score(data)
      expect(score).to(be < 100)
      expect(score).to(be > 0)
    end

    it("penalizes stale activity") do
      data = gem_data(last_commit: 2.years.ago)
      data[:latest_version_release_date] = 2.years.ago
      score = described_class.gem_score(data)
      expect(score).to(be < 100)
    end

    it("penalizes vulnerabilities") do
      data = gem_data(vuln_count: 1)
      score_1 = described_class.gem_score(data)
      data_3 = gem_data(vuln_count: 3)
      score_3 = described_class.gem_score(data_3)
      expect(score_1).to(be < 100)
      expect(score_3).to(be < score_1)
    end

    it("adapts weights when components are nil") do
      data = {
        libyear: nil,
        version_yanked: nil,
        archived: nil,
        last_commit_date: Time.now,
        latest_version_release_date: Time.now,
        latest_pre_release_version_release_date: nil,
        scorecard_score: nil,
        vulnerability_count: 0,
      }
      score = described_class.gem_score(data)
      # Only activity (100) and vulnerabilities (100) contribute
      expect(score).to(eq(100))
    end

    it("returns nil when all components are nil") do
      data = {
        libyear: nil,
        version_yanked: nil,
        archived: nil,
        last_commit_date: nil,
        latest_version_release_date: nil,
        latest_pre_release_version_release_date: nil,
        scorecard_score: nil,
        vulnerability_count: nil,
      }
      expect(described_class.gem_score(data)).to(be_nil)
    end
  end

  describe(".system_average") do
    it("averages per-gem scores") do
      result = {
        "a" => { health_score: 80 },
        "b" => { health_score: 60 },
      }
      expect(described_class.system_average(result)).to(eq(70))
    end

    it("skips nil scores") do
      result = {
        "a" => { health_score: 80 },
        "b" => { health_score: nil },
      }
      expect(described_class.system_average(result)).to(eq(80))
    end

    it("returns nil for empty result") do
      expect(described_class.system_average({})).to(be_nil)
    end
  end
end
