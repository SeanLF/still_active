# frozen_string_literal: true

require "json"
require "digest"
require "time"
require_relative "../still_active/sarif/rules"
require_relative "lockfile_indexer"
require_relative "activity_helper"
require_relative "constraint_helper"

module StillActive
  # Renders a still_active workflow result as a SARIF 2.1.0 document.
  # The output is suitable for upload to GitHub Code Scanning via
  # github/codeql-action/upload-sarif.
  module SarifHelper
    extend self

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    TOOL_NAME = "still_active"
    TOOL_URI = "https://github.com/SeanLF/still_active"

    LIBYEAR_THRESHOLD = 1.0
    SCORECARD_LOW_THRESHOLD = 4.0
    SECONDS_PER_YEAR = 365 * 24 * 60 * 60 # for the human-readable "in N years"

    # result: same hash StillActive::Workflow.call returns (gem_name => gem_data)
    # ruby_info: optional Ruby freshness hash (or nil)
    # lockfile_path: path to Gemfile.lock for line annotations
    # tool_version: StillActive::VERSION at emit time
    def render(result:, ruby_info:, lockfile_path:, tool_version:)
      lockfile_content = File.read(lockfile_path)
      line_index = LockfileIndexer.gem_line_index(lockfile_content)
      ruby_line = LockfileIndexer.ruby_version_line(lockfile_content)
      lockfile_uri = File.basename(lockfile_path)

      results = build_results(
        report: result,
        ruby_info: ruby_info,
        line_index: line_index,
        ruby_line: ruby_line,
        lockfile_uri: lockfile_uri,
      )

      JSON.pretty_generate(document(results: results, tool_version: tool_version))
    end

    private

    def document(results:, tool_version:)
      {
        "$schema" => SARIF_SCHEMA,
        "version" => "2.1.0",
        "runs" => [{
          "tool" => {
            "driver" => {
              "name" => TOOL_NAME,
              "semanticVersion" => tool_version,
              "informationUri" => TOOL_URI,
              "rules" => sarif_rules,
            },
          },
          "originalUriBaseIds" => { "%SRCROOT%" => { "uri" => "file:///" } },
          "results" => results,
          "columnKind" => "utf16CodeUnits",
        }],
      }
    end

    def sarif_rules
      Sarif::Rules.all.map { |r| sarif_rule(r) }
    end

    def sarif_rule(r)
      properties = { "tags" => r[:tags], "precision" => "high" }
      properties["security-severity"] = r[:security_severity] if r[:security_severity]
      {
        "id" => r[:id],
        "name" => r[:name],
        "shortDescription" => { "text" => r[:short] },
        "fullDescription" => { "text" => r[:full] },
        "help" => { "text" => r[:help_text], "markdown" => r[:help_markdown] },
        "helpUri" => Sarif::Rules.help_uri(r[:id]),
        "defaultConfiguration" => { "level" => r[:level] },
        "properties" => properties,
      }
    end

    def build_results(report:, ruby_info:, line_index:, ruby_line:, lockfile_uri:)
      results = []
      report.each do |gem_name, data|
        results.concat(gem_results(gem_name.to_s, data, line_index, lockfile_uri))
      end
      results << ruby_eol_result(ruby_info, ruby_line, lockfile_uri) if ruby_info && ruby_info[:eol]
      results
    end

    def gem_results(name, data, line_index, lockfile_uri)
      out = []
      version = data[:version_used]
      location = location_for(name, line_index, lockfile_uri)

      if data[:archived]
        out << mark_suppressed(result("SA001", name, "#{name} #{version}: upstream repository is archived#{repo_suffix(data)}#{alternatives_suffix(data)}#{transitive_suffix(data)}.", location), name, :activity)
      end

      unless data[:archived]
        if ActivityHelper.activity_level(data) == :critical
          activity = ActivityHelper.last_activity(data)
          years = ((Time.now - activity[:date]) / SECONDS_PER_YEAR).round(1)
          noun = activity[:kind] == :release ? "no release" : "no commits"
          out << mark_suppressed(
            result(
              "SA002",
              name,
              "#{name} #{version}: #{noun} in #{years} years (last #{activity[:date].utc.strftime("%Y-%m-%d")})#{alternatives_suffix(data)}#{transitive_suffix(data)}.",
              location,
            ),
            name,
            :activity,
          )
        end
      end

      Array(data[:vulnerabilities]).each do |vuln|
        out << vulnerability_result(name, version, vuln, location, data)
      end

      if data[:libyear] && data[:libyear] > LIBYEAR_THRESHOLD
        latest = data[:latest_version] ? " behind #{data[:latest_version]}" : ""
        out << mark_suppressed(result("SA004", name, "#{name} #{version}: #{data[:libyear]} libyears#{latest}#{transitive_suffix(data)}.", location), name, :libyear)
      end

      if data[:scorecard_score] && data[:scorecard_score] < SCORECARD_LOW_THRESHOLD
        out << mark_suppressed(result("SA005", name, "#{name} #{version}: OpenSSF Scorecard #{data[:scorecard_score]}/10 (low).", location), name, :scorecard)
      end

      if data[:version_yanked]
        out << mark_suppressed(result("SA007", name, "#{name} #{version}: this version has been yanked from RubyGems.", location), name, :yanked)
      end

      if data[:poison] && !Array(data[:constraints]).empty?
        # Level tracks the poison tier (critical->error, ...); a plain majors-behind
        # tier change keeps the (rule_id, gem_name) fingerprint so it doesn't re-alert.
        # But an escalation up the tiers (maintenance -> security-relevant -> below the
        # fix) adds a fingerprint dimension so a past dismissal of a weaker tier can't
        # silently mute the stronger one -- the transition a human must see.
        state = if data[:poison_below_fix]
          "below_fix"
        elsif data[:poison_security_relevant]
          "security"
        else
          "maintenance"
        end
        out << mark_suppressed(result("SA008", name, poison_message(name, version, data), location, level: poison_level(data), fp_extra: state), name, :poison)
      end

      if data[:language_ceiling]
        # Level tracks the ceiling tier: critical (EOL-forced) -> error, note
        # (latest-not-yet) -> note. Fingerprint is (rule_id, gem_name, state) where
        # state is the eol_forced boolean: cosmetic churn (which patch, which
        # latest) doesn't re-alert, but a note -> EOL-forced escalation (a supported
        # runtime went EOL) mints a NEW alert so a past dismissal of the note can't
        # silently mute the critical -- that transition is exactly the one a human
        # must see.
        state = data[:language_ceiling][:eol_forced] ? "eol_forced" : "latest_not_yet"
        out << mark_suppressed(result("SA009", name, language_ceiling_message(name, version, data), location, level: language_ceiling_level(data), fp_extra: state), name, :language_ceiling)
      end

      out
    end

    def language_ceiling_level(data)
      { critical: "error", warning: "warning", note: "note" }.fetch(data[:language_ceiling][:severity], "note")
    end

    def language_ceiling_message(name, version, data)
      ceiling = data[:language_ceiling]
      runtime = ceiling[:runtime]
      body =
        if ceiling[:eol_forced]
          eol = ceiling[:ceiling_eol_date]
          eol_part = eol ? " (EOL #{format_date(eol)})" : ""
          "stranding you on end-of-life #{runtime} #{ceiling[:ceiling_version]}#{eol_part}"
        else
          "no #{runtime} #{ceiling[:latest_stable]} support yet"
        end
      fix = ceiling[:fixed_by_upgrade] && data[:latest_version] ? "; upgrade to #{data[:latest_version]} to lift it" : ""
      "#{name} #{version}: requires #{runtime} #{ceiling[:requirement]}, #{body}#{fix}#{transitive_suffix(data)}."
    end

    # The poison receipt for a Code Scanning alert: the worst 3 caps (shared
    # ranking via ConstraintHelper.top_findings so it can't drift from the other
    # renderers) with the exact latest version (a machine-read alert wants the
    # precise version, not the "8.x" the terminal abbreviates to), plus "+N more"
    # and the transitive parent. Note result() fingerprints on (rule_id, gem_name)
    # only, so this volatile detail never re-alerts a finding the user triaged.
    def poison_level(data)
      # A security-relevant cap (a dormant dep pins a known-vulnerable dependency
      # below its fix) escalates to error regardless of majors-behind: it's a real
      # security finding, not the maintenance-tier signal poison usually is.
      return "error" if data[:poison_security_relevant]

      { critical: "error", warning: "warning", note: "note" }.fetch(data[:poison_severity], "warning")
    end

    def poison_message(name, version, data)
      top = ConstraintHelper.top_findings(Array(data[:constraints]), limit: 3)
      caps = top[:shown].map do |finding|
        behind = finding[:majors_behind]
        "#{finding[:dependency]} #{finding[:requirement]} (#{behind} major#{"s" unless behind == 1} behind, latest #{finding[:dep_latest]})"
      end
      remaining = top[:total] - top[:shown].length
      caps << "+#{remaining} more" if remaining.positive?
      "#{name} #{version}: caps #{caps.join("; ")}#{transitive_suffix(data)}#{poison_security_note(data)}."
    end

    # Spells out the security escalation for a code-scanning alert. Only claims
    # "below the fix" (with the CVE and its nearest fix, a version the cap forbids)
    # when that is actually established. Otherwise we say only that the dep is
    # known-vulnerable, WITHOUT asserting patchability: this branch also covers a
    # HIGH advisory with no released fix at all (class C), which is not patchable in
    # place, so an "(patchable in place)" claim here would be false on the worst case.
    def poison_security_note(data)
      return "" unless data[:poison_security_relevant]

      below = Array(data[:constraints]).select { |c| c[:capped_below_fix] }
      if below.any?
        receipts = below.map { |c| "#{c[:dependency]} below the fix (#{c[:below_fix_advisory]} fixed in #{c[:below_fix_fixed_in]}, outside the cap)" }.uniq
        " -- pins #{receipts.join("; ")}"
      else
        pinned = Array(data[:constraints]).select { |c| c[:capped_dep_vulnerable] }.map { |c| c[:dependency] }.uniq
        " -- pins known-vulnerable #{pinned.join(", ")}"
      end
    end

    # Attaches a SARIF native suppressions[] entry when this finding is covered
    # by a whole-gem --ignore or a granular .still_active.yml suppression, so a
    # GitHub code-scanning consumer renders it dismissed rather than open. The
    # suppression's reason rides along as the justification.
    def mark_suppressed(result_hash, gem_name, signal, advisory: nil, aliases: [])
      config = StillActive.config
      if config.ignored_gems.include?(gem_name)
        result_hash["suppressions"] = [{ "kind" => "external", "justification" => "ignored via --ignore" }]
        return result_hash
      end

      entry = config.suppressions.match(gem: gem_name, signal: signal, advisory: advisory, aliases: aliases)
      return result_hash unless entry

      suppression = { "kind" => "external" }
      suppression["justification"] = entry.reason if entry.reason
      result_hash["suppressions"] = [suppression]
      result_hash
    end

    def vulnerability_result(name, version, vuln, location, data = {})
      # Level tracks the resolved severity LABEL (a real CVSS score OR OSV's GHSA
      # label), so a CVSS-4-only HIGH -- which deps.dev returns as cvss3Score 0 --
      # exports as error, not a note/warning a code-scanning gate reads as
      # informational. The security-severity NUMBER stays tied to a real CVSS score
      # (effective_score): a label-only advisory carries no invented number rather
      # than a fabricated 7.0. A confirmed-but-unscored advisory still fails closed.
      score = VulnerabilityHelper.effective_score(vuln)
      level = Sarif::Rules.severity_to_level(VulnerabilityHelper.advisory_severity(vuln))
      severity = Sarif::Rules.cvss_to_security_severity(score)
      advisory_id = vuln[:id] || Array(vuln[:aliases]).first || "unknown"
      aliases = Array(vuln[:aliases]).first(3).join(", ")
      alias_suffix = aliases.empty? ? "" : " [#{aliases}]"
      title = vuln[:title] ? ": #{vuln[:title]}" : ""
      # ruby-advisory-db records no safe version: upgrading can't clear it, which
      # is the actionable distinction from an ordinary (patchable) advisory.
      no_fix = vuln[:no_fix_available] ? " (no fixed version available)" : ""

      base = result(
        "SA003",
        name,
        "#{name} #{version}: #{advisory_id}#{title}#{alias_suffix}#{no_fix}#{transitive_suffix(data)}.",
        location,
        level: level,
        fp_extra: advisory_id,
      )
      base["properties"] = { "security-severity" => severity } if severity
      mark_suppressed(base, name, :vulnerability, advisory: vuln[:id], aliases: Array(vuln[:aliases]))
    end

    # Names the direct dependency a transitive flagged gem rides in on, so a
    # code-scanning consumer gets the actionable "replace your direct gem" hop
    # instead of an un-actionable transitive finding (#60).
    def transitive_suffix(data)
      path = data[:dependency_path]
      return "" unless data[:direct] == false && path && path.length >= 2

      " (transitive, pulled in by #{path.first})"
    end

    def ruby_eol_result(ruby_info, ruby_line, lockfile_uri)
      version = ruby_info[:version]
      eol_part = ruby_info[:eol_date] ? " (EOL #{format_date(ruby_info[:eol_date])})" : ""
      latest_part = ruby_info[:latest_version] ? " Latest is #{ruby_info[:latest_version]}." : ""
      base = {
        "ruleId" => "SA006",
        "ruleIndex" => rule_index("SA006"),
        "level" => "error",
        "message" => { "text" => "Ruby #{version} has reached end-of-life#{eol_part}.#{latest_part}" },
        "locations" => [{
          "physicalLocation" => {
            "artifactLocation" => { "uri" => lockfile_uri, "uriBaseId" => "%SRCROOT%" },
            "region" => { "startLine" => ruby_line },
          },
        }],
      }
      apply_fingerprint(base, fingerprint("SA006", "ruby"))
    end

    def result(rule_id, gem_name, message, location, level: nil, fp_extra: nil)
      level ||= Sarif::Rules.find(rule_id)[:level]
      base = {
        "ruleId" => rule_id,
        "ruleIndex" => rule_index(rule_id),
        "level" => level,
        "message" => { "text" => message },
        "locations" => [location],
      }
      apply_fingerprint(base, fingerprint(rule_id, gem_name, fp_extra))
    end

    def apply_fingerprint(result, fp)
      result["partialFingerprints"] = {
        "primaryLocationLineHash" => fp,
        "stillActiveFinding/v1" => fp,
      }
      result
    end

    def location_for(gem_name, line_index, lockfile_uri)
      {
        "physicalLocation" => {
          "artifactLocation" => { "uri" => lockfile_uri, "uriBaseId" => "%SRCROOT%" },
          "region" => { "startLine" => line_index[gem_name] || 1 },
        },
      }
    end

    def fingerprint(rule_id, gem_name, advisory_id = nil)
      Digest::SHA256.hexdigest(["v1", rule_id, gem_name, advisory_id].compact.join("|"))[0, 16]
    end

    def rule_index(rule_id)
      Sarif::Rules.all.index { |r| r[:id] == rule_id }
    end

    def format_date(value)
      t = ActivityHelper.parse_time(value)
      t ? t.utc.strftime("%Y-%m-%d") : value.to_s
    end

    def repo_suffix(data)
      data[:repository_url] ? " (#{data[:repository_url]})" : ""
    end

    def alternatives_suffix(data)
      leads = data[:alternatives]
      return "" if leads.nil? || leads.empty?

      " Consider: #{leads.join(", ")}"
    end
  end
end
