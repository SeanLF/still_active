# frozen_string_literal: true

require_relative "markdown_escape"
require_relative "vulnerability_helper"
require_relative "activity_helper"
require_relative "constraint_helper"

module StillActive
  module MarkdownHelper
    extend self

    def ruby_line(ruby_info)
      version = ruby_info[:version]
      latest = ruby_info[:latest_version]
      libyear = ruby_info[:libyear]
      eol = ruby_info[:eol]
      eol_date = ruby_info[:eol_date]

      return "**Ruby #{version}** (latest) #{StillActive.config.success_emoji}" if version == latest

      libyear_part = libyear ? "#{libyear} libyears behind #{latest}" : "behind #{latest}"

      if eol
        eol_part = eol_date ? "EOL #{eol_date.strftime("%Y-%m-%d")}" : "EOL"
        "**Ruby #{version}** (#{eol_part}, #{libyear_part}) #{StillActive.config.critical_warning_emoji}"
      else
        "**Ruby #{version}** (#{libyear_part}) #{StillActive.config.warning_emoji}"
      end
    end

    def markdown_table_header_line
      "| activity | up to date? | OpenSSF | vulns | name | version used | latest version | latest pre-release | last commit | libyear | license |\n" \
        "| -------- | ----------- | ------- | ----- | ---- | ------------ | -------------- | ------------------ | ----------- | ------- | ------- |"
    end

    def markdown_table_body_line(gem_name:, data:)
      repository_url = data[:repository_url]
      ruby_gems_url = data[:ruby_gems_url]

      inactive_repository_emoji = data[:last_activity_warning_emoji]
      using_latest_version_emoji = data[:up_to_date_emoji]

      formatted_name = markdown_url(text: gem_name, url: repository_url)

      formatted_version_used = if [:git, :path].include?(data[:source_type])
        data[:version_used] ? "#{data[:version_used]} (#{data[:source_type]})" : "(#{data[:source_type]})"
      elsif data[:version_yanked]
        "#{data[:version_used]} (YANKED #{StillActive.config.critical_warning_emoji})"
      else
        version_with_date(
          text: data[:version_used],
          url: version_url(ruby_gems_url, data[:version_used]),
          date: data[:version_used_release_date],
        )
      end

      formatted_latest_version = version_with_date(
        text: data[:latest_version],
        url: version_url(ruby_gems_url, data[:latest_version]),
        date: data[:latest_version_release_date],
      )

      formatted_latest_pre_release = version_with_date(
        text: data[:latest_pre_release_version],
        url: version_url(ruby_gems_url, data[:latest_pre_release_version]),
        date: data[:latest_pre_release_version_release_date],
      )

      formatted_last_commit = markdown_url(text: year_month(data[:last_commit_date]), url: repository_url)

      unsure = StillActive.config.unsure_emoji

      cells = [
        inactive_repository_emoji || unsure,
        using_latest_version_emoji || unsure,
        format_scorecard(data[:scorecard_score]),
        format_vulns(data),
        formatted_name,
        formatted_version_used || unsure,
        formatted_latest_version || unsure,
        formatted_latest_pre_release || unsure,
        formatted_last_commit || unsure,
        format_libyear(data[:libyear]),
        format_license(data[:license]),
      ]

      "| #{cells.join(" | ")} |"
    end

    def alternatives_section(result)
      flagged = result.select do |_name, data|
        data[:alternatives] && !data[:alternatives].empty?
      end
      return "" if flagged.empty?

      lines = ["", "**Alternatives** (Ruby Toolbox leads, verify fit):"]
      flagged.each { |name, data| lines << "- #{MarkdownEscape.code_span(name)}: #{MarkdownEscape.inline(data[:alternatives].join(", "))}" }
      lines.join("\n")
    end

    # Flagged transitive gems can't be swapped directly; name the direct
    # dependency that pulls each one in so the finding becomes actionable (#60).
    def transitive_section(result)
      flagged = result.select do |_name, data|
        data[:direct] == false && Array(data[:dependency_path]).length >= 2 && transitive_flagged?(data)
      end
      return "" if flagged.empty?

      lines = ["", "**Transitive findings** (pulled in by a direct dependency):"]
      flagged.each do |name, data|
        lines << "- #{MarkdownEscape.code_span(name)} via #{MarkdownEscape.code_span(data[:dependency_path].first)}"
      end
      lines.join("\n")
    end

    # A dormant dep that caps your tree below its latest major (the poison-pill
    # signal). Consistent with the other finding sections: worst caps + total, the
    # direct parent named for a transitive pill. The full cap list is in the JSON.
    def poison_section(result)
      # Require constraints present, not just the poison flag, so an unexpected
      # empty set can't emit a dangling "- `gem` caps" bullet (symmetric with the
      # terminal's poison_line guard).
      flagged = result.select { |_name, data| data[:poison] && !Array(data[:constraints]).empty? }
      return "" if flagged.empty?

      lines = ["", "**Poison-pill findings** (dormant deps capping your tree below its latest major):"]
      # Worst-first so the act-now findings lead, then by magnitude for a stable,
      # triage-friendly order.
      ranked = flagged.sort_by do |name, data|
        [
          data[:poison_security_relevant] ? 0 : 1, # security-relevant caps lead
          -ConstraintHelper::SEVERITY.index(data[:poison_severity] || :note),
          -Array(data[:constraints]).map { |c| c[:majors_behind].to_i }.max,
          name.to_s,
        ]
      end
      ranked.each do |name, data|
        lines << "- **#{data[:poison_severity] || :note}** #{poison_gem_ref(name, data)} caps #{poison_caps(data[:constraints])}#{poison_security_marker(data)}"
      end
      lines.join("\n")
    end

    # A prominent marker naming the known-vulnerable dependency a security-relevant
    # cap pins you below the fix for -- the finding to act on first.
    def poison_security_marker(data)
      return "" unless data[:poison_security_relevant]

      pinned = Array(data[:constraints]).select { |c| c[:capped_dep_vulnerable] }.map { |c| c[:dependency] }.uniq
      " ⚠ **pins vulnerable #{pinned.join(", ")}**"
    end

    # The language-runtime ceiling: a resolved version whose declared runtime
    # constraint (Ruby `ruby_version`, Python `requires_python`) caps the runtime
    # onto an EOL release (critical) or below the latest stable (note). Ranked
    # worst-first with a tier label, mirroring the poison section.
    def language_ceiling_section(result)
      flagged = result.select { |_name, data| data[:language_ceiling] }
      return "" if flagged.empty?

      lines = ["", "**Runtime ceiling findings** (a resolved version capping the language runtime it can run on):"]
      ranked = flagged.sort_by { |name, data| [-ConstraintHelper::SEVERITY.index(data[:language_ceiling][:severity] || :note), name.to_s] }
      ranked.each do |name, data|
        ceiling = data[:language_ceiling]
        lines << "- **#{ceiling[:severity] || :note}** #{MarkdownEscape.code_span(name)} #{language_ceiling_receipt(ceiling, data)}"
      end
      lines.join("\n")
    end

    private

    def language_ceiling_receipt(ceiling, data)
      runtime = ceiling[:runtime]
      req = MarkdownEscape.code_span(ceiling[:requirement])
      base =
        if ceiling[:eol_forced]
          eol = ceiling[:ceiling_eol_date]
          eol_part = eol ? " (EOL #{eol.strftime("%Y-%m-%d")})" : ""
          "requires #{runtime} #{req}, stranding you on end-of-life #{runtime} #{ceiling[:ceiling_version]}#{eol_part}"
        else
          "requires #{runtime} #{req}, no #{runtime} #{ceiling[:latest_stable]} support yet"
        end
      fix = ceiling[:fixed_by_upgrade] && data[:latest_version] ? "; upgrade to #{data[:latest_version]} to lift it" : ""
      "#{base}#{fix}"
    end

    def poison_gem_ref(name, data)
      ref = MarkdownEscape.code_span(name)
      path = data[:dependency_path]
      # Transitive pill: name the direct parent the user can actually act on (#60).
      return ref unless data[:direct] == false && Array(path).length >= 2

      "#{ref} via #{MarkdownEscape.code_span(path.first)}"
    end

    # The worst 3 caps; the first carries the full receipt (requirement + latest
    # major), the rest just the gap, and "— N total" when there are more.
    def poison_caps(constraints)
      top = ConstraintHelper.top_findings(Array(constraints), limit: 3)
      parts = top[:shown].each_with_index.map do |finding, i|
        dep = MarkdownEscape.code_span(finding[:dependency])
        req = MarkdownEscape.code_span(finding[:requirement])
        behind = finding[:majors_behind]
        i.zero? ? "#{dep} #{req} (#{behind} major#{"s" unless behind == 1} behind, latest #{poison_major(finding[:dep_latest])})" : "#{dep} #{req} (#{behind})"
      end
      joined = parts.join(", ")
      top[:total] > 1 ? "#{joined} — #{top[:total]} total" : joined
    end

    # "8.0.1" -> "8.x": the cap is a major-level gap.
    def poison_major(version)
      major = version.to_s[/\d+/]
      major ? "#{major}.x" : version
    end

    def transitive_flagged?(data)
      [:archived, :critical].include?(ActivityHelper.activity_level(data)) || data[:vulnerability_count].to_i.positive?
    end

    def version_with_date(text:, url:, date:)
      version_part = markdown_url(text: text, url: url)
      return if version_part.nil?

      date_part = year_month(date)
      return version_part unless date_part

      "#{version_part} (#{date_part})"
    end

    def version_url(ruby_gems_url, version)
      return if ruby_gems_url.nil? || version.nil?

      "#{ruby_gems_url}/versions/#{version}"
    end

    def format_scorecard(score)
      return StillActive.config.unsure_emoji if score.nil?

      "#{score}/10"
    end

    def format_libyear(value)
      return "-" if value.nil?

      "#{value}y"
    end

    def format_license(license)
      return "-" if license.nil? || license.empty?

      MarkdownEscape.cell(license)
    end

    def format_vulns(data)
      count = data[:vulnerability_count]
      return StillActive.config.unsure_emoji if count.nil?
      return StillActive.config.success_emoji if count.zero?

      vulnerabilities = data[:vulnerabilities] || []
      severity = VulnerabilityHelper.highest_severity(vulnerabilities)
      ids = vulnerabilities.flat_map { |v| [v[:id], *v[:aliases]] }.compact.uniq.first(3)

      notes = [severity, ("no fix" if VulnerabilityHelper.no_fix_available?(vulnerabilities))].compact
      parts = [notes.empty? ? count.to_s : "#{count} (#{notes.join(", ")})"]
      parts << MarkdownEscape.cell(ids.join(", ")) unless ids.empty?
      parts.join(" ")
    end

    def markdown_url(text:, url:)
      safe_text = MarkdownEscape.link_text(text)
      return safe_text if url.nil?

      "[#{safe_text}](#{MarkdownEscape.url(url)})"
    end

    def year_month(time_object)
      return if time_object.nil?

      time_object.strftime("%Y/%m")
    end
  end
end
