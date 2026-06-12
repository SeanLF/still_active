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

    it("returns :stale for a commit-only gem 18 months to 3 years old (the no-release fallback)") do
      # No release data, so the last commit is the only signal (e.g. git-sourced).
      expect(described_class.activity_level(gem_data(last_commit: 2.years.ago))).to(eq(:stale))
    end

    it("returns :critical for activity older than 3 years") do
      expect(described_class.activity_level(gem_data(last_commit: 4.years.ago))).to(eq(:critical))
    end

    it("treats a release ~15 months old as :ok (the ok ceiling is 18 months, not 12)") do
      # Ruby gems release far less often than the npm-calibrated 12-month line
      # assumes; the ok ceiling is 18 months, measured against real RubyGems
      # cadence (mature staples like mime-types/bcrypt routinely exceed a year).
      expect(described_class.activity_level(gem_data(release: 450.days.ago))).to(eq(:ok))
    end

    it("returns :unknown when all dates are nil") do
      expect(described_class.activity_level(gem_data)).to(eq(:unknown))
    end

    it("uses the most recent release date, ignoring an older commit") do
      data = gem_data(last_commit: 4.years.ago, release: Time.now, pre_release: 2.years.ago)
      expect(described_class.activity_level(data)).to(eq(:ok))
    end

    it("does not let a recent commit mask a stale release (release recency drives the level)") do
      # The bug: a single fresh rubocop/README commit on a gem whose last real
      # release was years ago previously read as :ok. A consumer can't bundle
      # update to unreleased commits, so the release drives the level and the
      # commit is context only.
      data = gem_data(last_commit: Time.now, release: 4.years.ago)
      expect(described_class.activity_level(data)).to(eq(:critical))
    end

    it("ignores nil dates when finding the most recent") do
      data = gem_data(last_commit: nil, release: nil, pre_release: 2.years.ago)
      expect(described_class.activity_level(data)).to(eq(:stale))
    end

    it("returns :archived when repo is archived regardless of dates") do
      data = gem_data(last_commit: Time.now).merge(archived: true)
      expect(described_class.activity_level(data)).to(eq(:archived))
    end

    it("does not return :archived when archived is false") do
      data = gem_data(last_commit: Time.now).merge(archived: false)
      expect(described_class.activity_level(data)).to(eq(:ok))
    end
  end
end
