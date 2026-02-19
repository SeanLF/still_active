# frozen_string_literal: true

module StillActive
  module HealthScoreHelper
    extend self

    WEIGHTS = {
      version_freshness: 30,
      activity: 25,
      scorecard: 20,
      vulnerabilities: 25,
    }.freeze

    def gem_score(gem_data)
      components = {
        version_freshness: version_freshness_score(gem_data),
        activity: activity_score(gem_data),
        scorecard: scorecard_score(gem_data),
        vulnerabilities: vulnerability_score(gem_data),
      }

      available = components.compact
      return if available.empty?

      total_weight = available.keys.sum { |k| WEIGHTS[k] }
      weighted_sum = available.sum { |k, v| WEIGHTS[k] * v }
      (weighted_sum.to_f / total_weight).round
    end

    def system_average(result)
      scores = result.each_value.filter_map { |d| d[:health_score] }
      return if scores.empty?

      (scores.sum.to_f / scores.size).round
    end

    private

    def version_freshness_score(gem_data)
      return 0 if gem_data[:version_yanked]

      libyear = gem_data[:libyear]
      return if libyear.nil?

      [100 - (libyear * 20), 0].max.round
    end

    def activity_score(gem_data)
      case gem_data[:archived]
      when true then return 0
      end

      level = ActivityHelper.activity_level(gem_data)
      case level
      when :ok then 100
      when :stale then 40
      when :critical then 10
      when :unknown then nil
      end
    end

    def scorecard_score(gem_data)
      score = gem_data[:scorecard_score]
      return if score.nil?

      (score * 10).round
    end

    def vulnerability_score(gem_data)
      count = gem_data[:vulnerability_count]
      return if count.nil?

      case count
      when 0 then 100
      when 1 then 40
      when 2 then 20
      else 0
      end
    end
  end
end
