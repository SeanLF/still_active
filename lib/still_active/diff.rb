# frozen_string_literal: true

module StillActive
  # Compares two still_active JSON snapshots and produces a structured Diff.
  # Designed for PR review: surfaces regressions (CI-failable deltas) on top
  # of the full added/removed/bumped breakdown.
  #
  # Schema versions accepted: see SUPPORTED_SCHEMA_VERSIONS. A snapshot with
  # a higher schema_version is rejected loudly rather than silently parsed.
  module Diff
    SUPPORTED_SCHEMA_VERSIONS = [1].freeze

    SCORECARD_DROP_THRESHOLD = 1.0      # absolute drop to flag
    SCORECARD_GOOD_THRESHOLD = 7.0      # categorical threshold (good -> below-good)
    NEW_GEM_LIBYEAR_THRESHOLD = 0.5     # added gems already this far behind regress
    LIBYEAR_DELTA_THRESHOLD = 0.01      # floating-point fuzz

    class UnsupportedSchemaError < StandardError; end

    Added = Struct.new(:name, :data, keyword_init: true)
    Removed = Struct.new(:name, :data, keyword_init: true)
    Bumped = Struct.new(:name, :before_version, :after_version, :kind, :before, :after, keyword_init: true)
    SignalChange = Struct.new(:name, :changes, :before, :after, keyword_init: true)
    Regression = Struct.new(:kind, :gem, :detail, keyword_init: true)
    Result = Struct.new(:added, :removed, :bumped, :signal_changes, :regressions, :ruby, keyword_init: true)

    extend self

    def call(baseline:, current:)
      validate_schema!(baseline, "baseline")
      validate_schema!(current, "current")

      b_gems = baseline.fetch("gems", {})
      c_gems = current.fetch("gems", {})

      added = (c_gems.keys - b_gems.keys).sort.map { |n| Added.new(name: n, data: c_gems[n]) }
      removed = (b_gems.keys - c_gems.keys).sort.map { |n| Removed.new(name: n, data: b_gems[n]) }

      bumped = []
      signal_changes = []
      (b_gems.keys & c_gems.keys).sort.each do |name|
        before = b_gems[name]
        after = c_gems[name]
        if before["version_used"] != after["version_used"]
          bumped << Bumped.new(
            name: name,
            before_version: before["version_used"],
            after_version: after["version_used"],
            kind: classify_bump(before, after),
            before: before,
            after: after,
          )
        end
        changes = collect_signal_changes(before, after)
        signal_changes << SignalChange.new(name: name, changes: changes, before: before, after: after) if changes.any?
      end

      ruby = ruby_delta(baseline["ruby"], current["ruby"])
      regressions = collect_regressions(
        added: added,
        bumped: bumped,
        signal_changes: signal_changes,
        ruby_delta: ruby,
      )

      Result.new(
        added: added,
        removed: removed,
        bumped: bumped,
        signal_changes: signal_changes,
        regressions: regressions,
        ruby: ruby,
      )
    end

    def validate_schema!(snapshot, role)
      version = snapshot["schema_version"]
      return if SUPPORTED_SCHEMA_VERSIONS.include?(version)

      raise UnsupportedSchemaError, "#{role} has schema_version=#{version.inspect}; supported: #{SUPPORTED_SCHEMA_VERSIONS.join(", ")}"
    end

    # Categorises a version bump:
    # - :introduced_vulns  - new advisories appeared on the resolved version
    # - :closed_vulns      - all advisories cleared
    # - :older_relative    - libyear-to-latest grew (rare; usually unchanged)
    # - :fresher           - libyear-to-latest shrank
    # - :neutral           - no obvious signal change
    def classify_bump(before, after)
      opened = vuln_count(after) - vuln_count(before)
      return :introduced_vulns if opened.positive?
      return :closed_vulns if opened.negative?

      delta = (after["libyear"] || 0.0) - (before["libyear"] || 0.0)
      return :older_relative if delta > LIBYEAR_DELTA_THRESHOLD
      return :fresher if delta < -LIBYEAR_DELTA_THRESHOLD

      :neutral
    end

    def collect_signal_changes(before, after)
      changes = []

      if !before["archived"] && after["archived"]
        changes << { kind: :archived, from: false, to: true }
      end

      opened = vuln_count(after) - vuln_count(before)
      if opened.positive? && before["version_used"] == after["version_used"]
        # Set difference is enough for the common case. Edge case: an advisory
        # backfilled with a CVE alias alongside an existing GHSA can show up as
        # "new" in this list even though it's a re-keying of the same issue.
        # The vulnerability_count gate above keeps that to detail-string noise.
        new_ids = advisory_ids(after) - advisory_ids(before)
        changes << { kind: :new_vulnerability, from: vuln_count(before), to: vuln_count(after), ids: new_ids.first(3) }
      end

      if before["scorecard_score"] && after["scorecard_score"]
        drop = before["scorecard_score"] - after["scorecard_score"]
        # OSSF treats >= 7.0 as "good". A score landing at 7.0 stays good (a 7.5
        # -> 7.0 dip is noise within the safe zone). Only drops below 7.0 cross.
        crossed = before["scorecard_score"] >= SCORECARD_GOOD_THRESHOLD && after["scorecard_score"] < SCORECARD_GOOD_THRESHOLD
        if drop >= SCORECARD_DROP_THRESHOLD || crossed
          changes << { kind: :scorecard_dropped, from: before["scorecard_score"], to: after["scorecard_score"], crossed_good: crossed }
        end
      end

      if before["libyear"] && after["libyear"] && before["version_used"] == after["version_used"]
        # Same pinned version + libyear grew = upstream released and we didn't
        # follow. That IS a regression. If version_used moved forward we deliberately
        # don't flag — moving forward isn't a PR regression even when libyear-to-latest
        # technically grows (because upstream is releasing faster).
        delta = after["libyear"] - before["libyear"]
        if delta > LIBYEAR_DELTA_THRESHOLD
          changes << { kind: :libyear_worsened, from: before["libyear"], to: after["libyear"], delta: delta.round(2) }
        end
      end

      if !before["version_yanked"] && after["version_yanked"]
        changes << { kind: :version_yanked }
      end

      changes
    end

    def collect_regressions(added:, bumped:, signal_changes:, ruby_delta:)
      regs = []

      added.each do |a|
        data = a.data
        if vuln_count(data).positive?
          regs << Regression.new(kind: :new_gem_with_vulns, gem: a.name, detail: "#{vuln_count(data)} vulns at introduction")
        elsif data["archived"]
          regs << Regression.new(kind: :new_gem_archived, gem: a.name, detail: "added gem points at archived repo")
        elsif data["libyear"] && data["libyear"] > NEW_GEM_LIBYEAR_THRESHOLD
          regs << Regression.new(kind: :new_gem_stale, gem: a.name, detail: "added gem already #{data["libyear"]} libyears behind latest")
        end
      end

      bumped.each do |b|
        if b.kind == :introduced_vulns
          regs << Regression.new(
            kind: :bump_introduced_vulns,
            gem: b.name,
            detail: "#{b.before_version} -> #{b.after_version}",
          )
        end
      end

      signal_changes.each do |sc|
        sc.changes.each do |ch|
          case ch[:kind]
          when :archived
            regs << Regression.new(kind: :archived, gem: sc.name, detail: "repo archived since baseline")
          when :new_vulnerability
            ids = Array(ch[:ids]).join(", ")
            regs << Regression.new(kind: :new_vulnerability, gem: sc.name, detail: "#{ch[:from]} -> #{ch[:to]}#{" (#{ids})" unless ids.empty?}")
          when :scorecard_dropped
            note = ch[:crossed_good] ? " crossed #{SCORECARD_GOOD_THRESHOLD}" : ""
            regs << Regression.new(kind: :scorecard_dropped, gem: sc.name, detail: "#{ch[:from]} -> #{ch[:to]}#{note}")
          when :version_yanked
            regs << Regression.new(kind: :version_yanked, gem: sc.name, detail: "pinned version yanked from rubygems")
          when :libyear_worsened
            regs << Regression.new(
              kind: :libyear_worsened,
              gem: sc.name,
              detail: "libyear #{ch[:from]} -> #{ch[:to]} (+#{ch[:delta]}y; same pinned version)",
            )
          end
        end
      end

      if ruby_delta && ruby_delta[:newly_eol]
        regs << Regression.new(kind: :ruby_eol_introduced, gem: "(ruby)", detail: "Ruby #{ruby_delta[:to]} is now EOL")
      end

      regs
    end

    def ruby_delta(before, after)
      return if before.nil? && after.nil?

      before ||= {}
      after ||= {}
      {
        version_changed: before["version"] != after["version"],
        from: before["version"],
        to: after["version"],
        newly_eol: !before["eol"] && !!after["eol"],
        libyear_before: before["libyear"],
        libyear_after: after["libyear"],
      }
    end

    def vuln_count(data)
      data["vulnerability_count"].to_i
    end

    def advisory_ids(data)
      Array(data["vulnerabilities"]).flat_map { |v| [v["id"], *Array(v["aliases"])].compact }.uniq
    end
  end
end
