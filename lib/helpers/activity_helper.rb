# frozen_string_literal: true

require_relative "../still_active/core_ext"

module StillActive
  module ActivityHelper
    extend self

    using StillActive::CoreExt

    # Returns :archived, :ok, :stale, :critical, or :unknown
    def activity_level(gem_data)
      return :archived if gem_data[:archived]

      # Release recency drives the level: a release is what a consumer can
      # actually consume (you can't `bundle update` to unreleased commits), so a
      # lone rubocop/README commit on an otherwise-dormant gem must not mask a
      # multi-year release drought. The last commit date is surfaced as context
      # elsewhere but only stands in here when a gem has no releases at all (e.g.
      # a git-sourced gem), where it is the only signal available.
      most_recent = [
        gem_data[:latest_version_release_date],
        gem_data[:latest_pre_release_version_release_date],
      ].compact.max
      most_recent ||= gem_data[:last_commit_date]

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
