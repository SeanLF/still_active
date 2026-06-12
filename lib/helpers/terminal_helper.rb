# frozen_string_literal: true

require_relative "activity_helper"
require_relative "ansi_helper"
require_relative "summary_helper"
require_relative "libyear_helper"
require_relative "version_helper"
require_relative "vulnerability_helper"

module StillActive
  module TerminalHelper
    extend self

    HEADERS = ["Name", "Version", "Activity", "OpenSSF", "Vulns", "License"].freeze

    def render(result, ruby_info: nil)
      names = result.keys.sort
      rows = names.map { |name| build_row(name, result[name]) }
      widths = column_widths(rows)

      lines = []
      lines << header_line(widths)
      lines << separator_line(widths)
      names.each_with_index do |name, i|
        lines << row_line(rows[i], widths)
        data = result[name]
        # Transitive gems can't be swapped directly, so point at the direct
        # parent instead of suggesting alternatives for them (#60).
        extra = data[:direct] == false ? dependency_path_line(data) : alternatives_line(data)
        lines << extra if extra
      end
      lines << ""
      lines << summary_line(result)
      lines << ruby_summary_line(ruby_info) if ruby_info
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
        format_license(data[:license]),
      ]
    end

    def format_license(license)
      return AnsiHelper.dim("-") if license.nil? || license.empty?

      license
    end

    def format_version(data)
      used = data[:version_used]
      latest = data[:latest_version]
      source_type = data[:source_type]

      if [:git, :path].include?(source_type)
        label = AnsiHelper.dim("(#{source_type})")
        return used ? "#{used} #{label}" : label
      end

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
      return AnsiHelper.dim("-") if score.nil?

      text = "#{score}/10"
      if score >= 7.0
        AnsiHelper.green(text)
      elsif score < 4.0
        AnsiHelper.yellow(text)
      else
        text
      end
    end

    def format_vulns(data)
      count = data[:vulnerability_count]
      return AnsiHelper.dim("-") if count.nil?
      return AnsiHelper.green("0") if count.zero?

      severity = VulnerabilityHelper.highest_severity(data[:vulnerabilities])
      label = severity ? "#{count} (#{severity})" : count.to_s
      AnsiHelper.red(label)
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

    def alternatives_line(data)
      level = ActivityHelper.activity_level(data)
      return unless [:archived, :critical].include?(level)

      leads = data[:alternatives]
      if leads && !leads.empty?
        AnsiHelper.dim("  ↳ leads (Ruby Toolbox): #{leads.join(" · ")} (verify fit)")
      elsif !StillActive.config.alternatives
        AnsiHelper.dim("  ↳ run with --alternatives for maintained replacements")
      end
    end

    # For a flagged transitive gem, name the direct dependency that pulls it in,
    # the gem the user can actually act on (#60).
    def dependency_path_line(data)
      path = data[:dependency_path]
      return unless path && path.length >= 2

      level = ActivityHelper.activity_level(data)
      return unless [:archived, :critical].include?(level) || data[:vulnerability_count].to_i.positive?

      AnsiHelper.dim("  ↳ transitive, pulled in by #{path.first}")
    end

    def ruby_summary_line(ruby_info)
      version = ruby_info[:version]
      latest = ruby_info[:latest_version]
      libyear = ruby_info[:libyear]
      eol = ruby_info[:eol]
      eol_date = ruby_info[:eol_date]

      return AnsiHelper.green("Ruby #{version} (latest)") if version == latest

      libyear_part = libyear ? "#{libyear} libyears behind #{latest}" : "behind #{latest}"

      if eol
        eol_part = eol_date ? "EOL #{eol_date.strftime("%Y-%m-%d")}" : "EOL"
        AnsiHelper.red("Ruby #{version} (#{eol_part}, #{libyear_part})")
      else
        AnsiHelper.yellow("Ruby #{version} (#{libyear_part})")
      end
    end

    # Reuse the same digest the JSON output emits so the human summary line can
    # never drift from the machine one (the #63 "computed two ways" trap). The
    # terminal keeps a coarser grouping (critical folds into stale) and adds its
    # own yanked / total-libyear extras that the JSON digest doesn't carry.
    def summary_line(result)
      summary = SummaryHelper.summarize(result)
      active = summary[:activity][:ok]
      stale = summary[:activity][:stale] + summary[:activity][:critical]
      archived = summary[:activity][:archived]
      yanked = result.each_value.count { |d| d[:version_yanked] }

      parts = ["#{summary[:total_gems]} gems: #{summary[:up_to_date]} up to date, #{summary[:outdated]} outdated"]
      parts.last << ", #{yanked} yanked" if yanked > 0
      activity = "#{active} active, #{stale} stale"
      activity << ", #{archived} archived" if archived > 0
      parts << activity
      parts << "#{summary[:vulnerabilities]} vulnerabilities"
      total_libyear = LibyearHelper.total_libyear(result)
      parts << "#{total_libyear.round(1)} libyears behind" if total_libyear > 0
      parts.join(" · ")
    end
  end
end
