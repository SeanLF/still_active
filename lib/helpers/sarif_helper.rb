# frozen_string_literal: true

require "json"
require "digest"
require "time"
require_relative "../still_active/sarif/rules"
require_relative "lockfile_indexer"
require_relative "activity_helper"

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
        out << result("SA001", name, "#{name} #{version}: upstream repository is archived#{repo_suffix(data)}#{alternatives_suffix(data)}.", location)
      end

      unless data[:archived]
        if ActivityHelper.activity_level(data) == :critical
          activity = ActivityHelper.last_activity(data)
          years = ((Time.now - activity[:date]) / SECONDS_PER_YEAR).round(1)
          noun = activity[:kind] == :release ? "no release" : "no commits"
          out << result(
            "SA002",
            name,
            "#{name} #{version}: #{noun} in #{years} years (last #{activity[:date].utc.strftime("%Y-%m-%d")})#{alternatives_suffix(data)}.",
            location,
          )
        end
      end

      Array(data[:vulnerabilities]).each do |vuln|
        out << vulnerability_result(name, version, vuln, location)
      end

      if data[:libyear] && data[:libyear] > LIBYEAR_THRESHOLD
        latest = data[:latest_version] ? " behind #{data[:latest_version]}" : ""
        out << result("SA004", name, "#{name} #{version}: #{data[:libyear]} libyears#{latest}.", location)
      end

      if data[:scorecard_score] && data[:scorecard_score] < SCORECARD_LOW_THRESHOLD
        out << result("SA005", name, "#{name} #{version}: OpenSSF Scorecard #{data[:scorecard_score]}/10 (low).", location)
      end

      if data[:version_yanked]
        out << result("SA007", name, "#{name} #{version}: this version has been yanked from RubyGems.", location)
      end

      out
    end

    def vulnerability_result(name, version, vuln, location)
      score = vuln[:cvss3_score] || vuln[:cvss2_score]
      level = Sarif::Rules.cvss_to_level(score)
      severity = Sarif::Rules.cvss_to_security_severity(score)
      advisory_id = vuln[:id] || Array(vuln[:aliases]).first || "unknown"
      aliases = Array(vuln[:aliases]).first(3).join(", ")
      alias_suffix = aliases.empty? ? "" : " [#{aliases}]"
      title = vuln[:title] ? ": #{vuln[:title]}" : ""

      base = result(
        "SA003",
        name,
        "#{name} #{version}: #{advisory_id}#{title}#{alias_suffix}.",
        location,
        level: level,
        fp_extra: advisory_id,
      )
      base["properties"] = { "security-severity" => severity } if severity
      base
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
