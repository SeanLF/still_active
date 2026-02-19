# frozen_string_literal: true

module StillActive
  module LibyearHelper
    extend self

    SECONDS_PER_YEAR = 31_556_952.0 # Gregorian average (365.2425 days)

    def gem_libyear(version_used_release_date:, latest_version_release_date:)
      return if version_used_release_date.nil? || latest_version_release_date.nil?

      diff = latest_version_release_date - version_used_release_date
      [diff / SECONDS_PER_YEAR, 0.0].max.round(1)
    end

    def total_libyear(result)
      result.each_value.sum { |d| d[:libyear] || 0.0 }
    end
  end
end
