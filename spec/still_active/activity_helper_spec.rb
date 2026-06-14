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

    # The 18-month and 3-year cutoffs are Signal A's whole point, and both
    # comparisons are inclusive (>=). Freeze now so the test's boundary date and
    # the one activity_level recomputes internally are the same instant; a
    # >= -> > regression flips the exactly-on-boundary cases and these catch it.
    context("when activity sits on a threshold boundary (defaults: 18 months ok, 3 years stale)") do
      let(:now) { Time.utc(2026, 6, 14, 12, 0, 0) }

      before { allow(Time).to(receive(:now).and_return(now)) }

      it("is :ok exactly at the 18-month ok boundary (inclusive)") do
        expect(described_class.activity_level(gem_data(release: 1.5.years.ago))).to(eq(:ok))
      end

      it("is :stale one second past the 18-month boundary") do
        expect(described_class.activity_level(gem_data(release: 1.5.years.ago - 1))).to(eq(:stale))
      end

      it("is :stale exactly at the 3-year stale boundary (inclusive)") do
        expect(described_class.activity_level(gem_data(release: 3.years.ago))).to(eq(:stale))
      end

      it("is :critical one second past the 3-year boundary") do
        expect(described_class.activity_level(gem_data(release: 3.years.ago - 1))).to(eq(:critical))
      end
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

  describe(".last_activity") do
    it("returns the most recent release tagged :release, ignoring a newer commit") do
      result = described_class.last_activity(gem_data(release: 2.years.ago, pre_release: 5.years.ago, last_commit: Time.now))
      expect(result[:kind]).to(eq(:release))
      expect(result[:date]).to(be_within(1).of(2.years.ago))
    end

    it("falls back to the commit date tagged :commit when there are no releases") do
      expect(described_class.last_activity(gem_data(last_commit: 2.years.ago))[:kind]).to(eq(:commit))
    end

    it("returns nil when there is no activity at all") do
      expect(described_class.last_activity(gem_data)).to(be_nil)
    end

    it("parses iso8601 string dates, which the SARIF path may supply") do
      expect(described_class.last_activity(gem_data(release: 2.years.ago.iso8601))[:kind]).to(eq(:release))
    end
  end
end
