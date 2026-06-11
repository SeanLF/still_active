# frozen_string_literal: true

require_relative "markdown_escape"

module StillActive
  # Renders a StillActive::Diff::Result as PR-comment-friendly markdown.
  # Section taxonomy mirrors GitHub's dependency-review-action so reviewers
  # already know where to look: Regressions / Added / Removed / Bumps /
  # Signal changes / Ruby. Empty sections are skipped.
  module DiffMarkdownHelper
    extend self

    BUMP_KIND_LABELS = {
      closed_vulns: "closed vulns",
      introduced_vulns: "INTRODUCED vulns",
      fresher: "fresher",
      older_relative: "older relative to latest",
      neutral: nil,
      unknown: nil,
    }.freeze

    def render(diff)
      sections = [
        "## still_active diff",
        "",
        summary_line(diff),
        "",
        regressions_section(diff.regressions),
        added_section(diff.added),
        removed_section(diff.removed),
        bumps_section(diff.bumped),
        signal_changes_section(diff.signal_changes),
        ruby_section(diff.ruby),
      ].reject(&:empty?)

      "#{sections.join("\n")}\n"
    end

    private

    def summary_line(diff)
      [
        ["regressions", diff.regressions.size],
        ["added", diff.added.size],
        ["removed", diff.removed.size],
        ["bumped", diff.bumped.size],
        ["signal-changes", diff.signal_changes.size],
      ].map { |label, n| "#{n} #{label}" }.join(" · ")
    end

    def regressions_section(regressions)
      return "" if regressions.empty?

      lines = regressions.map { |r| "- **#{r.kind}** #{MarkdownEscape.code_span(r.gem)} — #{MarkdownEscape.inline(r.detail)}" }
      section("Regressions (CI-failable)", lines)
    end

    def added_section(added)
      return "" if added.empty?

      lines = added.map { |a| "- #{format_added(a)}" }
      section("Added", lines)
    end

    def removed_section(removed)
      return "" if removed.empty?

      lines = removed.map { |r| "- #{MarkdownEscape.code_span(r.name)} (was #{MarkdownEscape.inline((r.data || {})["version_used"] || "?")})" }
      section("Removed", lines)
    end

    def bumps_section(bumped)
      return "" if bumped.empty?

      lines = bumped.map { |b| format_bump(b) }
      section("Version bumps", lines)
    end

    def signal_changes_section(signal_changes)
      return "" if signal_changes.empty?

      lines = signal_changes.flat_map { |sc| format_signal_change_lines(sc) }
      section("Signal changes (same version)", lines)
    end

    def ruby_section(ruby)
      return "" if ruby.nil?
      return "" unless ruby[:version_changed] || ruby[:newly_eol]

      lines = []
      if ruby[:version_changed]
        eol_suffix = ruby[:newly_eol] ? " (now EOL)" : ""
        lines << "- Ruby #{MarkdownEscape.code_span(ruby[:from])} → #{MarkdownEscape.code_span(ruby[:to])}#{eol_suffix}"
      elsif ruby[:newly_eol]
        lines << "- Ruby #{MarkdownEscape.code_span(ruby[:to])} is now EOL"
      end
      section("Ruby", lines)
    end

    def section(title, lines)
      "### #{title}\n\n#{lines.join("\n")}\n"
    end

    def format_added(added)
      data = added.data || {}
      bits = [
        data["version_used"] && "v#{data["version_used"]}",
        data["scorecard_score"] && "OpenSSF #{data["scorecard_score"]}",
        (data["vulnerability_count"].to_i.positive? ? "#{data["vulnerability_count"]} vulns" : nil),
        (data["archived"] ? "archived" : nil),
        data["libyear"] && "#{data["libyear"]}y behind",
      ].compact
      "#{MarkdownEscape.code_span(added.name)} (#{MarkdownEscape.inline(bits.join(", "))})"
    end

    def format_bump(bump)
      label = BUMP_KIND_LABELS[bump.kind]
      suffix = label ? " (#{label})" : ""
      "- #{MarkdownEscape.code_span(bump.name)} #{MarkdownEscape.inline(bump.before_version)} → #{MarkdownEscape.inline(bump.after_version)}#{suffix}"
    end

    def format_signal_change_lines(sc)
      name = MarkdownEscape.code_span(sc.name)
      sc.changes.filter_map do |ch|
        case ch[:kind]
        when :archived
          "- #{name} — archived (false → true)"
        when :new_vulnerability
          ids = MarkdownEscape.inline(Array(ch[:ids]).join(", "))
          "- #{name} — new vulnerability (#{MarkdownEscape.inline(ch[:from])} → #{MarkdownEscape.inline(ch[:to])}#{" — #{ids}" unless ids.empty?})"
        when :scorecard_dropped
          note = ch[:crossed_good] ? " (crossed 7.0)" : ""
          "- #{name} — scorecard #{MarkdownEscape.inline(ch[:from])} → #{MarkdownEscape.inline(ch[:to])}#{note}"
        when :version_yanked
          "- #{name} — version yanked from rubygems"
        when :libyear_worsened
          "- #{name} — libyear #{MarkdownEscape.inline(ch[:from])} → #{MarkdownEscape.inline(ch[:to])} (+#{ch[:delta]}y; same pinned version)"
        end
      end
    end
  end
end
