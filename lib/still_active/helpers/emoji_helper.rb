# frozen_string_literal: true

require_relative "activity_helper"
require_relative "repository_check"

module StillActive
  module EmojiHelper
    extend self

    def inactive_gem_emoji(result_hash)
      case ActivityHelper.activity_level(result_hash)
      when :ok then RepositoryCheck.unanswered?(result_hash) ? StillActive.config.unsure_emoji : ""
      when :stale then StillActive.config.warning_emoji
      when :archived, :critical then StillActive.config.critical_warning_emoji
      when :unknown then StillActive.config.unsure_emoji
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
