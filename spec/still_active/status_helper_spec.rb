# frozen_string_literal: true

require_relative "../../lib/still_active/helpers/status_helper"

RSpec.describe(StillActive::StatusHelper) do
  # activity_level reads the global activity thresholds, so reset to defaults
  # before each example to stay independent of any spec that tuned them.
  before { StillActive.reset }

  def recent = (Time.now - (30 * 24 * 60 * 60)) # ~1 month ago -> :ok
  def ancient = (Time.now - (5 * 365 * 24 * 60 * 60)) # ~5 years ago -> dormant

  describe(".gem_status") do
    it("is :vulnerable for an actively-released gem with a vulnerability (fixable)") do
      data = {latest_version_release_date: recent, vulnerability_count: 1}
      expect(described_class.gem_status(data)).to(eq(:vulnerable))
    end

    it("is :unknown when the pinned version doesn't resolve (never :ok on a nonexistent/yanked version)") do
      # A pinned version the registry has no record of can't be assessed: package-level
      # health must not read a nonexistent version as :ok. Absence of data stays :unknown.
      data = {version_unresolved: true, latest_version_release_date: recent, vulnerability_count: 0}
      expect(described_class.gem_status(data)).to(eq(:unknown))
    end

    it("is :dead for a dormant gem with an unpatched vulnerability (no one is fixing it)") do
      data = {latest_version_release_date: ancient, vulnerability_count: 1}
      expect(described_class.gem_status(data)).to(eq(:dead))
    end

    it("is :dead for an archived gem with a vulnerability") do
      data = {archived: true, vulnerability_count: 2}
      expect(described_class.gem_status(data)).to(eq(:dead))
    end

    it("is :archived for an archived repo with no recent releases or vulnerabilities") do
      data = {archived: true, latest_version_release_date: ancient, vulnerability_count: 0}
      expect(described_class.gem_status(data)).to(eq(:archived))
    end

    it("is :archived for an archived repo with no release data at all") do
      data = {archived: true, vulnerability_count: 0}
      expect(described_class.gem_status(data)).to(eq(:archived))
    end

    it("is :stale (not :archived) when the repo is archived but the gem still publishes recent releases (monorepo consolidation)") do
      data = {archived: true, latest_version_release_date: recent, vulnerability_count: 0}
      expect(described_class.gem_status(data)).to(eq(:stale))
    end

    it("is :legacy for a clean, long-dormant gem (years old, no vulns) -- 'done', not critical") do
      data = {latest_version_release_date: ancient, vulnerability_count: 0}
      expect(described_class.gem_status(data)).to(eq(:legacy))
    end

    it("is :ok for a recently released, unflagged gem") do
      data = {latest_version_release_date: recent, vulnerability_count: 0}
      expect(described_class.gem_status(data)).to(eq(:ok))
    end

    it("is :unknown when there is no activity data and vulnerabilities were not measured") do
      expect(described_class.gem_status({})).to(eq(:unknown))
    end

    it("does not let an unmeasured vulnerability count read as vulnerable") do
      data = {latest_version_release_date: recent} # vulnerability_count absent
      expect(described_class.gem_status(data)).to(eq(:ok))
    end
  end

  describe(".project_status") do
    it("is the worst status across all gems (archived outranks a legacy/done gem)") do
      result = {
        "a" => {latest_version_release_date: recent, vulnerability_count: 0}, # ok
        "b" => {archived: true, vulnerability_count: 0},                      # archived
        "c" => {latest_version_release_date: ancient, vulnerability_count: 0} # legacy
      }
      expect(described_class.project_status(result)).to(eq(:archived))
    end

    it("is :dead when any gem is dead, outranking a vulnerable gem") do
      result = {
        "a" => {latest_version_release_date: recent, vulnerability_count: 1},  # vulnerable
        "b" => {latest_version_release_date: ancient, vulnerability_count: 1} # dead
      }
      expect(described_class.project_status(result)).to(eq(:dead))
    end

    it("ranks :legacy below :stale (a clean done gem is less concerning than a drifting one)") do
      stale_date = Time.now - (2 * 365 * 24 * 60 * 60) # ~2 years -> :stale (18mo-3yr window)
      result = {
        "a" => {latest_version_release_date: ancient, vulnerability_count: 0},     # legacy
        "b" => {latest_version_release_date: stale_date, vulnerability_count: 0}  # stale
      }
      expect(described_class.project_status(result)).to(eq(:stale))
    end

    it("floors the project at :vulnerable when Ruby is EOL even if every gem is ok") do
      result = {"a" => {latest_version_release_date: recent, vulnerability_count: 0}}
      expect(described_class.project_status(result, ruby_info: {eol: true})).to(eq(:vulnerable))
    end

    it("is :unknown for an empty result") do
      expect(described_class.project_status({})).to(eq(:unknown))
    end

    it("ignores :unknown gems when a known status is present") do
      result = {
        "a" => {}, # unknown
        "b" => {latest_version_release_date: recent, vulnerability_count: 0} # ok
      }
      expect(described_class.project_status(result)).to(eq(:ok))
    end
  end
end
