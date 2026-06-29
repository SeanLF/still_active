# frozen_string_literal: true

require_relative "../../lib/helpers/status_helper"

RSpec.describe(StillActive::StatusHelper) do
  def recent = (Time.now - (30 * 24 * 60 * 60)) # ~1 month ago -> :ok
  def ancient = (Time.now - (5 * 365 * 24 * 60 * 60)) # ~5 years ago -> :critical

  describe(".gem_status") do
    it("is :vulnerable when the gem has any vulnerability, even if otherwise fresh") do
      data = { latest_version_release_date: recent, vulnerability_count: 1 }
      expect(described_class.gem_status(data)).to(eq(:vulnerable))
    end

    it("is :vulnerable in preference to :archived") do
      data = { archived: true, vulnerability_count: 2 }
      expect(described_class.gem_status(data)).to(eq(:vulnerable))
    end

    it("is :archived for an archived repo with no vulnerabilities") do
      data = { archived: true, vulnerability_count: 0 }
      expect(described_class.gem_status(data)).to(eq(:archived))
    end

    it("is :ok for a recently released, unflagged gem") do
      data = { latest_version_release_date: recent, vulnerability_count: 0 }
      expect(described_class.gem_status(data)).to(eq(:ok))
    end

    it("is :critical for a gem whose last release is years old") do
      data = { latest_version_release_date: ancient, vulnerability_count: 0 }
      expect(described_class.gem_status(data)).to(eq(:critical))
    end

    it("is :unknown when there is no activity data and vulnerabilities were not measured") do
      expect(described_class.gem_status({})).to(eq(:unknown))
    end

    it("does not let an unmeasured vulnerability count read as vulnerable") do
      data = { latest_version_release_date: recent } # vulnerability_count absent
      expect(described_class.gem_status(data)).to(eq(:ok))
    end
  end

  describe(".project_status") do
    it("is the worst status across all gems") do
      result = {
        "a" => { latest_version_release_date: recent, vulnerability_count: 0 }, # ok
        "b" => { archived: true, vulnerability_count: 0 },                      # archived
        "c" => { latest_version_release_date: ancient, vulnerability_count: 0 }, # critical
      }
      expect(described_class.project_status(result)).to(eq(:archived))
    end

    it("is :vulnerable when any gem is vulnerable") do
      result = {
        "a" => { latest_version_release_date: recent, vulnerability_count: 0 },
        "b" => { latest_version_release_date: recent, vulnerability_count: 1 },
      }
      expect(described_class.project_status(result)).to(eq(:vulnerable))
    end

    it("is at least :critical when Ruby is EOL even if every gem is ok") do
      result = { "a" => { latest_version_release_date: recent, vulnerability_count: 0 } }
      expect(described_class.project_status(result, ruby_info: { eol: true })).to(eq(:critical))
    end

    it("is :unknown for an empty result") do
      expect(described_class.project_status({})).to(eq(:unknown))
    end

    it("ignores :unknown gems when a known status is present") do
      result = {
        "a" => {}, # unknown
        "b" => { latest_version_release_date: recent, vulnerability_count: 0 }, # ok
      }
      expect(described_class.project_status(result)).to(eq(:ok))
    end
  end
end
