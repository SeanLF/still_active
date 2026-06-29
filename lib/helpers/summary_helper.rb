# frozen_string_literal: true

require_relative "activity_helper"
require_relative "status_helper"

module StillActive
  # Builds the JSON output's summary{} digest: the headline posture of the audit
  # in one object, so a machine/LLM consumer reads the totals directly instead
  # of iterating every gem. Counts are derived from the canonical per-gem fields
  # (activity_level, archived, up_to_date, vulnerability_count) so they never
  # drift from a separately-thresholded SARIF rule.
  module SummaryHelper
    ACTIVITY_LEVELS = [:ok, :stale, :critical, :archived, :unknown].freeze

    extend self

    def summarize(result, ruby_info: nil)
      activity = ACTIVITY_LEVELS.to_h { |level| [level, 0] }
      archived = up_to_date = outdated = vulnerable_gems = vulnerabilities = direct = 0

      result.each_value do |data|
        activity[ActivityHelper.activity_level(data)] += 1
        direct += 1 if data[:direct]
        archived += 1 if data[:archived]
        up_to_date += 1 if data[:up_to_date] == true
        outdated += 1 if data[:up_to_date] == false
        count = data[:vulnerability_count].to_i
        next unless count.positive?

        vulnerable_gems += 1
        vulnerabilities += count
      end

      summary = {
        total_gems: result.size,
        direct: direct,
        transitive: result.size - direct,
        activity: activity,
        archived: archived,
        up_to_date: up_to_date,
        outdated: outdated,
        vulnerable_gems: vulnerable_gems,
        vulnerabilities: vulnerabilities,
        # The single worst per-gem verdict (plus EOL Ruby), so a consumer reads
        # one project-level posture without scanning every gem's status.
        status: StatusHelper.project_status(result, ruby_info: ruby_info),
      }
      summary[:ruby_eol] = ruby_info[:eol] == true if ruby_info
      summary
    end
  end
end
