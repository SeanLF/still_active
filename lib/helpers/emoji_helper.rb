# frozen_string_literal: true

module StillActive
  module EmojiHelper
    extend self
    def inactive_gem_emoji(result_hash)
      most_recent_activity = [result_hash.dig(:version_used_release_date), result_hash.dig(:latest_version_release_date),
                              result_hash.dig(:latest_pre_release_version_release_date),].compact.sort.last
      return "❓" if most_recent_activity.nil?

      case ((Time.now - most_recent_activity) / ONE_YEAR_IN_SECONDS).ceil
      when 0..1
        ""
      when 2..3
        "\u26A0\uFE0F"
      else
        "\u{1F6A9}"
      end
    end

    def using_latest_emoji(using_last_release:, using_last_pre_release:)
      if using_last_release.nil? && using_last_pre_release.nil?
        "❓"
      elsif using_last_release
        "✅"
      elsif using_last_pre_release
        "🔮"
      else
        "⚠️"
      end
    end

    ONE_YEAR_IN_SECONDS = 3.154e+7
  end
end
