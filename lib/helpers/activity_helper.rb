# frozen_string_literal: true

require_relative "../still_active/core_ext"

module StillActive
  module ActivityHelper
    extend self

    using StillActive::CoreExt

    # Returns :ok, :stale, :critical, or :unknown
    def activity_level(gem_data)
      most_recent = [
        gem_data[:last_commit_date],
        gem_data[:latest_version_release_date],
        gem_data[:latest_pre_release_version_release_date],
      ].compact.max

      return :unknown if most_recent.nil?

      config = StillActive.config
      if most_recent >= config.no_warning_range_end.years.ago
        :ok
      elsif most_recent >= config.warning_range_end.years.ago
        :stale
      else
        :critical
      end
    end
  end
end
