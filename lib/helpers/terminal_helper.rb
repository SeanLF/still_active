# frozen_string_literal: true

require_relative "activity_helper"
require_relative "ansi_helper"
require_relative "libyear_helper"
require_relative "version_helper"

module StillActive
  module TerminalHelper
    extend self

    HEADERS = ["Name", "Version", "Activity", "OpenSSF", "Vulns"].freeze

    def render(result)
      rows = result.keys.sort.map { |name| build_row(name, result[name]) }
      widths = column_widths(rows)

      lines = []
      lines << header_line(widths)
      lines << separator_line(widths)
      rows.each { |row| lines << row_line(row, widths) }
      lines << ""
      lines << summary_line(result)
      lines.join("\n")
    end

    private

    def build_row(name, data)
      [
        name,
        format_version(data),
        format_activity(data),
        format_scorecard(data[:scorecard_score]),
        format_vulns(data),
      ]
    end

    def format_version(data)
      used = data[:version_used]
      latest = data[:latest_version]
      return AnsiHelper.dim("-") if used.nil? && latest.nil?
      return AnsiHelper.red("#{used} (YANKED)") if data[:version_yanked]

      if VersionHelper.up_to_date(version_used: used, latest_version: latest)
        AnsiHelper.green("#{used} (latest)")
      elsif latest
        AnsiHelper.yellow("#{used} → #{latest}")
      else
        used.to_s
      end
    end

    def format_activity(data)
      case ActivityHelper.activity_level(data)
      when :archived then AnsiHelper.red("archived")
      when :ok then AnsiHelper.green("ok")
      when :stale then AnsiHelper.yellow("stale")
      when :critical then AnsiHelper.red("critical")
      when :unknown then AnsiHelper.dim("-")
      end
    end

    def format_scorecard(score)
      score.nil? ? AnsiHelper.dim("-") : "#{score}/10"
    end

    def format_vulns(data)
      count = data[:vulnerability_count]
      return AnsiHelper.dim("-") if count.nil?
      return AnsiHelper.green("0") if count.zero?

      severity = highest_severity(data[:vulnerabilities])
      label = severity ? "#{count} (#{severity})" : count.to_s
      AnsiHelper.red(label)
    end

    def highest_severity(vulnerabilities)
      return if vulnerabilities.nil? || vulnerabilities.empty?

      max_score = vulnerabilities.filter_map { |v| v[:cvss3_score] }.max
      return if max_score.nil?

      case max_score
      when 9.0..Float::INFINITY then "critical"
      when 7.0...9.0 then "high"
      when 4.0...7.0 then "medium"
      else "low"
      end
    end

    def column_widths(rows)
      return HEADERS.map { |h| h.length + 2 } if rows.empty?

      HEADERS.zip(rows.transpose).map do |header, cells|
        widths = cells.map { AnsiHelper.visible_length(_1) }
        [header.length, *widths].max + 2
      end
    end

    def header_line(widths)
      HEADERS.zip(widths)
        .map { |h, w| AnsiHelper.pad(AnsiHelper.bold(h), w) }
        .join
    end

    def separator_line(widths)
      AnsiHelper.dim(widths.map { |w| "─" * w }.join)
    end

    def row_line(row, widths)
      row.zip(widths)
        .map { |cell, w| AnsiHelper.pad(cell, w) }
        .join
    end

    def summary_line(result)
      total = result.size
      level_counts = result.each_value.map { |d| ActivityHelper.activity_level(d) }.tally
      version_counts = result.each_value
        .map { |d| VersionHelper.up_to_date(version_used: d[:version_used], latest_version: d[:latest_version]) }
        .tally

      up_to_date = version_counts.fetch(true, 0)
      outdated = version_counts.fetch(false, 0)
      yanked = result.each_value.count { |d| d[:version_yanked] }
      active = level_counts.fetch(:ok, 0)
      archived = level_counts.fetch(:archived, 0)
      stale = level_counts.fetch(:stale, 0) + level_counts.fetch(:critical, 0) + archived
      vulns = result.each_value.sum { |d| d[:vulnerability_count] || 0 }

      parts = [
        "#{total} gems: #{up_to_date} up to date, #{outdated} outdated",
      ]
      parts.last << ", #{yanked} yanked" if yanked > 0
      parts << "#{active} active, #{stale} stale"
      parts << "#{vulns} vulnerabilities"
      total_libyear = LibyearHelper.total_libyear(result)
      parts << "#{total_libyear.round(1)} libyears behind" if total_libyear > 0
      parts.join(" · ")
    end
  end
end
