# frozen_string_literal: true

require_relative "../still_active/core_ext"

module StillActive
  module EmojiHelper
    extend self

    using StillActive::CoreExt

    def inactive_gem_emoji(result_hash)
      most_recent_activity = [
        result_hash[:last_commit_date],
        result_hash[:latest_version_release_date],
        result_hash[:latest_pre_release_version_release_date],
      ].compact.sort.last
      return StillActive.config.unsure_emoji if most_recent_activity.nil?

      case most_recent_activity
      when (StillActive.config.no_warning_range_end.years.ago)..(Time.now)
        ""
      when (StillActive.config.warning_range_end.years.ago)..(StillActive.config.no_warning_range_end.years.ago)
        StillActive.config.warning_emoji
      else
        StillActive.config.critical_warning_emoji
      end
    end

    def using_latest_emoji(using_last_release:, using_last_pre_release:)
      if using_last_release.nil? && using_last_pre_release.nil?
        StillActive.config.unsure_emoji
      elsif using_last_pre_release
        StillActive.config.futurist_emoji
      elsif using_last_release
        StillActive.config.success_emoji
      else
        StillActive.config.warning_emoji
      end
    end
  end
end
