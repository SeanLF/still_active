# frozen_string_literal: true

require_relative "../../lib/helpers/libyear_helper"

RSpec.describe(StillActive::LibyearHelper) do
  describe(".gem_libyear") do
    it("returns years between two dates") do
      used = Time.new(2023, 1, 1)
      latest = Time.new(2025, 1, 1)
      expect(described_class.gem_libyear(version_used_release_date: used, latest_version_release_date: latest)).to(eq(2.0))
    end

    it("returns 0.0 when dates are the same") do
      now = Time.now
      expect(described_class.gem_libyear(version_used_release_date: now, latest_version_release_date: now)).to(eq(0.0))
    end

    it("returns nil when version_used_release_date is nil") do
      expect(described_class.gem_libyear(version_used_release_date: nil, latest_version_release_date: Time.now)).to(be_nil)
    end

    it("returns nil when latest_version_release_date is nil") do
      expect(described_class.gem_libyear(version_used_release_date: Time.now, latest_version_release_date: nil)).to(be_nil)
    end

    it("clamps to 0.0 when used version is newer than latest") do
      used = Time.new(2025, 6, 1)
      latest = Time.new(2025, 1, 1)
      expect(described_class.gem_libyear(version_used_release_date: used, latest_version_release_date: latest)).to(eq(0.0))
    end
  end

  describe(".total_libyear") do
    it("sums libyear values across gems") do
      result = {
        "a" => { libyear: 1.5 },
        "b" => { libyear: 2.3 },
      }
      expect(described_class.total_libyear(result)).to(eq(3.8))
    end

    it("treats nil libyear as 0") do
      result = {
        "a" => { libyear: 1.0 },
        "b" => { libyear: nil },
      }
      expect(described_class.total_libyear(result)).to(eq(1.0))
    end

    it("returns 0 for empty result") do
      expect(described_class.total_libyear({})).to(eq(0.0))
    end
  end
end
