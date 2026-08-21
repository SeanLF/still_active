# frozen_string_literal: true

require "time"
require_relative "../core_ext"

module StillActive
  module ActivityHelper
    extend self

    using StillActive::CoreExt

    # The most recent activity signal that drives the level, or nil if none:
    # { date:, kind: } where kind is :release (preferred) or :commit. Release
    # recency drives the level because a release is what a consumer can actually
    # consume (you can't `bundle update` to unreleased commits), so a lone
    # rubocop/README commit can't mask a multi-year release drought. The commit
    # date stands in only when a gem has no releases at all (e.g. a git-sourced
    # gem), where it is the only signal available.
    def last_activity(gem_data)
      release = [
        gem_data[:latest_version_release_date],
        gem_data[:latest_pre_release_version_release_date]
      ].filter_map { parse_time(_1) }.max
      return {date: release, kind: :release} if release

      commit = parse_time(gem_data[:last_commit_date])
      commit ? {date: commit, kind: :commit} : nil
    end

    # Coerce a Time or an iso8601-ish string (the SARIF path may supply either)
    # to a Time, or nil if absent/unparseable.
    def parse_time(value)
      return value if value.is_a?(Time)
      return if value.nil?

      Time.parse(value.to_s)
    rescue ArgumentError, TypeError, RangeError
      nil
    end

    # Returns :archived, :ok, :stale, :critical, or :unknown
    def activity_level(gem_data)
      return :archived if gem_data[:archived]

      release_recency_level(gem_data)
    end

    # Recency verdict from release/commit dates alone, ignoring the archived
    # flag: :ok, :stale, :critical, or :unknown. Lets the lifecycle status tell
    # an archived-but-still-publishing gem (development moved to a monorepo) from
    # a genuinely dormant one.
    def release_recency_level(gem_data)
      activity = last_activity(gem_data)
      return :unknown if activity.nil?

      config = StillActive.config
      if activity[:date] >= config.no_warning_range_end.years.ago
        :ok
      elsif activity[:date] >= config.warning_range_end.years.ago
        :stale
      else
        :critical
      end
    end
  end
end
