# frozen_string_literal: true

require_relative "../../lib/still_active/core_ext"

using StillActive::CoreExt

RSpec.describe(StillActive::EmojiHelper) do
  before { StillActive.reset }

  let(:config) { StillActive.config }

  describe("#inactive_gem_emoji") do
    def gem_data(last_commit: nil, release: nil, pre_release: nil)
      { last_commit_date: last_commit, latest_version_release_date: release, latest_pre_release_version_release_date: pre_release }
    end

    it("returns empty string for a gem with recent commit") do
      expect(described_class.inactive_gem_emoji(gem_data(last_commit: Time.now))).to(eq(""))
    end

    it("returns empty string for a gem with recent release") do
      expect(described_class.inactive_gem_emoji(gem_data(release: Time.now))).to(eq(""))
    end

    it("returns empty string when any date is recent") do
      expect(described_class.inactive_gem_emoji(gem_data(last_commit: 4.years.ago, release: Time.now))).to(eq(""))
    end

    it("returns warning emoji for stale gem (1-3 years)") do
      expect(described_class.inactive_gem_emoji(gem_data(last_commit: 2.years.ago))).to(eq(config.warning_emoji))
    end

    it("returns warning emoji when most recent date is in warning range") do
      expect(described_class.inactive_gem_emoji(gem_data(last_commit: 4.years.ago, release: 2.years.ago))).to(eq(config.warning_emoji))
    end

    it("returns critical emoji for very old gem (>3 years)") do
      expect(described_class.inactive_gem_emoji(gem_data(last_commit: 4.years.ago))).to(eq(config.critical_warning_emoji))
    end

    it("returns unsure emoji when all dates are nil") do
      expect(described_class.inactive_gem_emoji(gem_data)).to(eq(config.unsure_emoji))
    end
  end

  describe("#using_latest_emoji") do
    it("returns unsure emoji when both values are nil") do
      expect(described_class.using_latest_emoji(using_last_release: nil, using_last_pre_release: nil)).to(eq(config.unsure_emoji))
    end

    it("returns success emoji when using latest release") do
      expect(described_class.using_latest_emoji(using_last_release: true, using_last_pre_release: nil)).to(eq(config.success_emoji))
    end

    it("returns success emoji when using latest release and not pre-release") do
      expect(described_class.using_latest_emoji(using_last_release: true, using_last_pre_release: false)).to(eq(config.success_emoji))
    end

    it("returns futurist emoji when using pre-release") do
      expect(described_class.using_latest_emoji(using_last_release: nil, using_last_pre_release: true)).to(eq(config.futurist_emoji))
    end

    it("returns futurist emoji when using both latest and pre-release") do
      expect(described_class.using_latest_emoji(using_last_release: true, using_last_pre_release: true)).to(eq(config.futurist_emoji))
    end

    it("returns warning emoji when not using latest release") do
      expect(described_class.using_latest_emoji(using_last_release: false, using_last_pre_release: nil)).to(eq(config.warning_emoji))
    end

    it("returns warning emoji when not using latest release or pre-release") do
      expect(described_class.using_latest_emoji(using_last_release: false, using_last_pre_release: false)).to(eq(config.warning_emoji))
    end

    it("returns warning emoji when release is nil and pre-release is false") do
      expect(described_class.using_latest_emoji(using_last_release: nil, using_last_pre_release: false)).to(eq(config.warning_emoji))
    end

    it("returns futurist emoji when release is false but pre-release is true") do
      expect(described_class.using_latest_emoji(using_last_release: false, using_last_pre_release: true)).to(eq(config.futurist_emoji))
    end
  end
end
