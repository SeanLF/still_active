# frozen_string_literal: true

require_relative "../../lib/still_active/core_ext"

using StillActive::CoreExt

RSpec.describe(StillActive::ActivityHelper) do
  before { StillActive.reset }

  def gem_data(last_commit: nil, release: nil, pre_release: nil)
    {
      last_commit_date: last_commit,
      latest_version_release_date: release,
      latest_pre_release_version_release_date: pre_release,
    }
  end

  describe(".activity_level") do
    it("returns :ok for recent activity") do
      expect(described_class.activity_level(gem_data(last_commit: Time.now))).to(eq(:ok))
    end

    it("returns :stale for activity between 1 and 3 years ago") do
      expect(described_class.activity_level(gem_data(last_commit: 2.years.ago))).to(eq(:stale))
    end

    it("returns :critical for activity older than 3 years") do
      expect(described_class.activity_level(gem_data(last_commit: 4.years.ago))).to(eq(:critical))
    end

    it("returns :unknown when all dates are nil") do
      expect(described_class.activity_level(gem_data)).to(eq(:unknown))
    end

    it("uses the most recent date across all fields") do
      data = gem_data(last_commit: 4.years.ago, release: Time.now, pre_release: 2.years.ago)
      expect(described_class.activity_level(data)).to(eq(:ok))
    end

    it("ignores nil dates when finding the most recent") do
      data = gem_data(last_commit: nil, release: nil, pre_release: 2.years.ago)
      expect(described_class.activity_level(data)).to(eq(:stale))
    end
  end
end
