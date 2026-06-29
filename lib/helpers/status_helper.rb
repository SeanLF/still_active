# frozen_string_literal: true

require_relative "activity_helper"

module StillActive
  # Collapses a gem's several maintenance signals into one categorical verdict,
  # so a machine/LLM consumer (or another tool's report) can display and threshold
  # a single value instead of re-deriving it from activity_level + archived +
  # vulnerability_count. This is deliberately NOT a numeric composite: an earlier
  # 0-100 score was removed because a weighted average let missing data read as
  # "perfect health". Here, :unknown stays :unknown -- absence of data is never
  # rendered as :ok.
  module StatusHelper
    extend self

    # Worst-first. A known vulnerability is the most actionable single concern;
    # below it, activity_level already ranks archived > critical > stale > ok;
    # :unknown (no data) is least severe because it is an absence, not a finding.
    SEVERITY = [:unknown, :ok, :stale, :critical, :archived, :vulnerable].freeze

    # Returns :vulnerable, :archived, :critical, :stale, :ok, or :unknown.
    def gem_status(gem_data)
      return :vulnerable if gem_data[:vulnerability_count].to_i.positive?

      ActivityHelper.activity_level(gem_data)
    end

    # The single worst gem status across the audit, with an EOL Ruby raising the
    # floor to :critical. :unknown only wins when nothing better is known.
    def project_status(result, ruby_info: nil)
      statuses = result.each_value.map { |data| gem_status(data) }
      statuses << :critical if ruby_info&.dig(:eol) == true
      return :unknown if statuses.empty?

      # Every value gem_status returns is in SEVERITY today; if a future status
      # isn't, rank it most-severe so it surfaces in the rollup rather than being
      # silently masked by a milder finding.
      statuses.max_by { |status| SEVERITY.index(status) || SEVERITY.length }
    end
  end
end
