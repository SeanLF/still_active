# frozen_string_literal: true

require_relative "activity_helper"
require_relative "ansi_helper"
require_relative "constraint_helper"
require_relative "dependency_helper"
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
        lines.concat(sub_lines(result[name]))
      end
      lines << ""
      lines << summary_line(result)
      lines << ruby_summary_line(ruby_info) if ruby_info
      lines.join("\n")
    end

    private

    # "dependencies" for a cross-ecosystem SBOM audit (the lens sets :ecosystem),
    # "gems" for a native Ruby audit -- calling npm/cargo/go packages "gems" is a
    # Ruby-ism that reads wrong cross-ecosystem.
    def dependency_noun(result)
      result.each_value.any? { |data| data[:ecosystem] } ? "dependencies" : "gems"
    end

    def build_row(name, data)
      [
        DependencyHelper.identity(name, data),
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

      # up_to_date is tri-state: true (on latest), false (genuinely behind), or nil
      # (a version Gem::Version can't parse -- a pypi epoch, an exotic build string).
      # Only paint the "-> latest" upgrade arrow on a definite false; a nil means we
      # couldn't compare, so show the version plainly rather than a false "behind"
      # (markdown shows unsure via its emoji tri-state for the same case).
      current = VersionHelper.up_to_date(version_used: used, latest_version: latest)
      if current
        AnsiHelper.green("#{used} (latest)")
      elsif current == false && latest
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
      notes = [severity, ("no fix" if VulnerabilityHelper.no_fix_available?(data[:vulnerabilities]))].compact
      label = notes.empty? ? count.to_s : "#{count} (#{notes.join(", ")})"
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

    # The ↳ sub-lines under a gem row. A poison gem gets the poison receipt (which
    # names the direct parent itself when transitive, so the generic transitive
    # line is redundant and dropped); a direct poison gem may still get its
    # alternatives line. A non-poison gem keeps the prior behaviour: transitive
    # gems point at the parent (#60), direct ones offer alternatives.
    def sub_lines(data)
      lines = if data[:poison]
        [poison_line(data), (data[:direct] == false ? nil : alternatives_line(data))]
      else
        [data[:direct] == false ? dependency_path_line(data) : alternatives_line(data)]
      end
      # A language-runtime ceiling is orthogonal to poison/alternatives (a gem can
      # be maintained yet still cap your Ruby), so it always gets its own line.
      lines << language_ceiling_line(data)
      lines.compact
    end

    # "  ↳ ruby ceiling: <receipt>" (or "python ceiling"), coloured by tier (red =
    # strands you on an EOL runtime, dim = an FYI cap below the latest stable).
    # Reuses poison_colour; the runtime name comes off the finding, not hardcoded.
    def language_ceiling_line(data)
      ceiling = data[:language_ceiling]
      return if ceiling.nil?

      AnsiHelper.public_send(poison_colour(ceiling[:severity]), "  ↳ #{ceiling[:runtime].downcase} ceiling: #{language_ceiling_receipt(ceiling, data)}")
    end

    def language_ceiling_receipt(ceiling, data)
      runtime = ceiling[:runtime]
      base =
        if ceiling[:eol_forced]
          "requires #{runtime} #{ceiling[:requirement]}, stranding you on end-of-life #{runtime} #{ceiling[:ceiling_version]}#{eol_suffix(ceiling[:ceiling_eol_date])}"
        else
          "requires #{runtime} #{ceiling[:requirement]}, no #{runtime} #{ceiling[:latest_stable]} support yet"
        end
      "#{base}#{language_ceiling_fix_hint(ceiling, data)}"
    end

    def eol_suffix(eol_date)
      eol_date ? " (EOL #{eol_date.strftime("%Y-%m-%d")})" : ""
    end

    # Name the actionable fix when a newer release of the gem lifts the cap; the
    # gem's own name sits on the row directly above, so "upgrade to <latest>" reads
    # unambiguously without repeating it.
    def language_ceiling_fix_hint(ceiling, data)
      return "" unless ceiling[:fixed_by_upgrade] && data[:latest_version]

      "; upgrade to #{data[:latest_version]} to lift it"
    end

    # "  ↳ poison: caps <receipt>", coloured by severity tier (see poison_colour).
    # The row is already red (poison requires a dormant gem); the sub-line tier
    # says how urgent the cap is. Transitive gems name the direct parent that pulls
    # the pill in, the actionable target.
    def poison_line(data)
      constraints = data[:constraints]
      return if constraints.nil? || constraints.empty?

      path = data[:dependency_path]
      via = data[:direct] == false && path && path.length >= 2 ? " (via #{path.first})" : ""
      # Colour carries the tier: red = act-now (3+ majors behind), yellow = plan,
      # dim = a minor/FYI cap (1 behind). A security-relevant cap (it pins a
      # vulnerable dependency below the fix) is always red -- that's the finding to
      # act on regardless of how many majors behind it happens to be.
      colour = data[:poison_security_relevant] ? :red : poison_colour(data[:poison_severity])
      AnsiHelper.public_send(colour, "  ↳ poison#{via}: #{poison_receipt(constraints)}#{poison_security_suffix(data)}")
    end

    # Names the vulnerable dependency a security-relevant poison cap pins you to. When
    # the cap holds you BELOW THE FIX (every patched version is a major it forbids) we
    # lead with that stronger, enforced claim and name the CVE and its nearest fix --
    # "you cannot patch this without replacing the dormant capper". Otherwise the
    # weaker "pins vulnerable X" (the dep is vulnerable, but patchable in place).
    def poison_security_suffix(data)
      return "" unless data[:poison_security_relevant]

      below = Array(data[:constraints]).select { |c| c[:capped_below_fix] }
      if below.any?
        receipts = below.map { |c| "#{c[:dependency]} below the fix (#{c[:below_fix_advisory]} fixed in #{c[:below_fix_fixed_in]})" }.uniq
        " ⚠ pins #{receipts.join("; ")}"
      else
        pinned = Array(data[:constraints]).select { |c| c[:capped_dep_vulnerable] }.map { |c| c[:dependency] }.uniq
        " ⚠ pins vulnerable #{pinned.join(", ")}"
      end
    end

    def poison_colour(severity)
      { critical: :red, warning: :yellow, note: :dim }.fetch(severity, :yellow)
    end

    # A worst-first "N label (X critical, Y note)" summary fragment, coloured by
    # the worst tier present, or nil when there are none. Shared by the poison and
    # Ruby-ceiling counts (both roll a set of tiered findings up the same way).
    def tier_summary_part(severities, label)
      return if severities.empty?

      by_tier = severities.group_by { |severity| severity || :note }
      present = ConstraintHelper::SEVERITY.reverse.select { |tier| by_tier[tier] } # worst-first
      breakdown = present.map { |tier| "#{by_tier[tier].size} #{tier}" }.join(", ")
      AnsiHelper.public_send(poison_colour(present.first), "#{label} (#{breakdown})")
    end

    # Single cap: the full receipt (requirement + latest major), since there's
    # room. Many caps: the worst 3 by majors-behind + "+N more", a glanceable
    # summary; the complete list stays in the JSON output.
    def poison_receipt(constraints)
      top = ConstraintHelper.top_findings(constraints, limit: 3)
      return single_cap_receipt(top[:shown].first) if top[:total] == 1

      parts = top[:shown].each_with_index.map do |finding, i|
        count = finding[:majors_behind]
        i.zero? ? "#{finding[:dependency]} (#{count} behind)" : "#{finding[:dependency]} (#{count})"
      end
      remaining = top[:total] - top[:shown].length
      receipt = "caps #{parts.join(", ")}"
      remaining.positive? ? "#{receipt} +#{remaining} more" : receipt
    end

    def single_cap_receipt(finding)
      behind = finding[:majors_behind]
      "caps #{finding[:dependency]} #{finding[:requirement]} " \
        "(#{behind} major#{"s" unless behind == 1} behind, latest #{major_x(finding[:dep_latest])})"
    end

    # "8.0.1" -> "8.x": the cap is a major-level gap, so the major is the honest
    # granularity to name as the current latest.
    def major_x(version)
      major = version.to_s[/\d+/]
      major ? "#{major}.x" : version
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

      parts = ["#{summary[:total_gems]} #{dependency_noun(result)}: #{summary[:up_to_date]} up to date, #{summary[:outdated]} outdated"]
      parts.last << ", #{yanked} yanked" if yanked > 0
      activity = "#{active} active, #{stale} stale"
      activity << ", #{archived} archived" if archived > 0
      parts << activity
      parts << "#{summary[:vulnerabilities]} vulnerabilities"
      poison_tiers = result.each_value.select { |data| data[:poison] }.map { |data| data[:poison_severity] }
      poison_part = tier_summary_part(poison_tiers, "#{poison_tiers.size} poison-#{poison_tiers.size == 1 ? "pill" : "pills"}")
      parts << poison_part if poison_part
      ceilings = result.each_value.filter_map { |data| data[:language_ceiling] }
      runtimes = ceilings.map { |ceiling| ceiling[:runtime] }.uniq
      runtime_label = runtimes.size == 1 ? runtimes.first : "language"
      ceiling_part = tier_summary_part(ceilings.map { |ceiling| ceiling[:severity] }, "#{ceilings.size} #{runtime_label} ceiling#{"s" unless ceilings.size == 1}")
      parts << ceiling_part if ceiling_part
      total_libyear = LibyearHelper.total_libyear(result)
      parts << "#{total_libyear.round(1)} libyears behind" if total_libyear > 0
      parts.join(" · ")
    end
  end
end
