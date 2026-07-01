# frozen_string_literal: true

require "json"
require "json_schemer"
require_relative "../../lib/helpers/sarif_helper"

RSpec.describe(StillActive::SarifHelper) do
  let(:lockfile_path) { File.expand_path("../fixtures/sarif/Gemfile.lock", __dir__) }
  let(:schema_path) { File.expand_path("../fixtures/sarif/sarif-schema-2.1.0.json", __dir__) }
  let(:tool_version) { "1.4.0" }

  def render(result:, ruby_info: nil)
    JSON.parse(described_class.render(
      result: result,
      ruby_info: ruby_info,
      lockfile_path: lockfile_path,
      tool_version: tool_version,
    ))
  end

  describe(".render envelope") do
    subject(:doc) { render(result: {}) }

    it("emits SARIF 2.1.0 version") do
      expect(doc["version"]).to(eq("2.1.0"))
    end

    it("declares the tool with semantic version") do
      driver = doc.dig("runs", 0, "tool", "driver")
      expect(driver["name"]).to(eq("still_active"))
      expect(driver["semanticVersion"]).to(eq("1.4.0"))
      expect(driver["informationUri"]).to(include("github.com/SeanLF/still_active"))
    end

    it("emits all 8 rules in tool.driver.rules with required fields") do
      rules = doc.dig("runs", 0, "tool", "driver", "rules")
      expect(rules.size).to(eq(8))
      rules.each do |r|
        expect(r).to(include("id", "name", "shortDescription", "fullDescription", "help", "helpUri", "defaultConfiguration", "properties"))
        expect(r["help"]).to(include("text", "markdown"))
        expect(r["properties"]["tags"]).to(be_a(Array))
        expect(r["properties"]["precision"]).to(eq("high"))
      end
    end

    it("includes security-severity on security rules only") do
      rules = doc.dig("runs", 0, "tool", "driver", "rules")
      by_id = rules.to_h { |r| [r["id"], r] }
      ["SA001", "SA003", "SA006", "SA007"].each do |id|
        expect(by_id[id]["properties"]["security-severity"]).to(match(/\A\d+\.\d+\z/))
      end
      ["SA002", "SA004", "SA005", "SA008"].each do |id|
        expect(by_id[id]["properties"]).not_to(have_key("security-severity"))
      end
    end

    it("declares originalUriBaseIds for source-root resolution") do
      expect(doc.dig("runs", 0, "originalUriBaseIds", "%SRCROOT%", "uri")).to(eq("file:///"))
    end

    it("emits an empty results array for an empty report") do
      expect(doc.dig("runs", 0, "results")).to(eq([]))
    end
  end

  describe("SA001 ArchivedRepository") do
    subject(:results) { render(result: report).dig("runs", 0, "results") }

    let(:report) { { "archived_gem" => { version_used: "1.0.0", archived: true, repository_url: "https://github.com/x/y" } } }

    it("emits one result per archived gem") do
      sa001 = results.select { |r| r["ruleId"] == "SA001" }
      expect(sa001.size).to(eq(1))
      expect(sa001[0]["level"]).to(eq("error"))
      expect(sa001[0]["message"]["text"]).to(include("archived_gem"))
    end

    it("points the location at the correct Gemfile.lock line") do
      sa001 = results.find { |r| r["ruleId"] == "SA001" }
      loc = sa001["locations"][0]["physicalLocation"]
      expect(loc["artifactLocation"]["uri"]).to(eq("Gemfile.lock"))
      expect(loc["region"]["startLine"]).to(eq(4))
    end

    it("uses a fingerprint that omits version") do
      report_v2 = { "archived_gem" => { version_used: "9.9.9", archived: true } }
      fp_a = render(result: report).dig("runs", 0, "results", 0, "partialFingerprints", "stillActiveFinding/v1")
      fp_b = render(result: report_v2).dig("runs", 0, "results", 0, "partialFingerprints", "stillActiveFinding/v1")
      expect(fp_a).to(eq(fp_b))
    end

    it("mirrors fingerprint to primaryLocationLineHash") do
      fps = render(result: report).dig("runs", 0, "results", 0, "partialFingerprints")
      expect(fps["primaryLocationLineHash"]).to(eq(fps["stillActiveFinding/v1"]))
    end
  end

  describe("native suppressions[] from .still_active.yml") do
    subject(:results) { render(result: report).dig("runs", 0, "results") }

    let(:report) { { "archived_gem" => { version_used: "1.0.0", archived: true, repository_url: "https://github.com/x/y" } } }

    before { StillActive.reset }

    after { StillActive.reset }

    it("marks a suppressed activity finding with the reason as justification") do
      StillActive.config.suppressions = StillActive::Suppressions.from([{ "gem" => "archived_gem", "signal" => "activity", "reason" => "vendored fork" }])
      sa001 = results.find { |r| r["ruleId"] == "SA001" }
      expect(sa001["suppressions"]).to(eq([{ "kind" => "external", "justification" => "vendored fork" }]))
    end

    it("leaves an unrelated finding unsuppressed") do
      StillActive.config.suppressions = StillActive::Suppressions.from([{ "gem" => "other", "signal" => "activity" }])
      expect(results.find { |r| r["ruleId"] == "SA001" }).not_to(have_key("suppressions"))
    end

    it("marks a whole-gem --ignore'd finding as suppressed") do
      StillActive.config.ignored_gems = ["archived_gem"]
      sa001 = results.find { |r| r["ruleId"] == "SA001" }
      expect(sa001.dig("suppressions", 0, "kind")).to(eq("external"))
    end

    it("marks only the matching advisory on a vulnerability finding") do
      StillActive.config.suppressions = StillActive::Suppressions.from([{ "gem" => "vg", "advisory" => "CVE-1", "reason" => "no fix" }])
      rpt = { "vg" => { version_used: "1.0.0", vulnerabilities: [{ id: "CVE-1" }, { id: "CVE-2" }] } }
      sa003 = render(result: rpt).dig("runs", 0, "results").select { |r| r["ruleId"] == "SA003" }
      suppressed = sa003.select { |r| r.key?("suppressions") }
      expect(suppressed.size).to(eq(1))
      expect(suppressed[0]["message"]["text"]).to(include("CVE-1"))
    end
  end

  describe("alternatives suffix") do
    it("appends alternatives to the archived-gem result message") do
      result = { "paperclip" => { source_type: :rubygems, version_used: "6.0.0", archived: true, alternatives: ["shrine", "carrierwave"] } }
      sarif = render(result: result)
      msg = sarif.dig("runs", 0, "results").find { |r| r["ruleId"] == "SA001" }.dig("message", "text")
      expect(msg).to(include("Consider: shrine, carrierwave"))
    end

    it("appends alternatives to the abandoned-gem result message") do
      ancient = Time.now - (4 * 365 * 24 * 60 * 60)
      result = { "paperclip" => { version_used: "6.0.0", archived: false, latest_version_release_date: ancient, alternatives: ["shrine", "carrierwave"] } }
      sarif = render(result: result)
      msg = sarif.dig("runs", 0, "results").find { |r| r["ruleId"] == "SA002" }.dig("message", "text")
      expect(msg).to(include("Consider: shrine, carrierwave"))
    end

    it("omits alternatives suffix when alternatives key is absent") do
      result = { "archived_gem" => { version_used: "1.0.0", archived: true } }
      sarif = render(result: result)
      msg = sarif.dig("runs", 0, "results").find { |r| r["ruleId"] == "SA001" }.dig("message", "text")
      expect(msg).not_to(include("Consider:"))
    end

    it("omits alternatives suffix when alternatives array is empty") do
      result = { "archived_gem" => { version_used: "1.0.0", archived: true, alternatives: [] } }
      sarif = render(result: result)
      msg = sarif.dig("runs", 0, "results").find { |r| r["ruleId"] == "SA001" }.dig("message", "text")
      expect(msg).not_to(include("Consider:"))
    end
  end

  describe("SA002 AbandonedGem") do
    # Release-driven, matching the rest of the tool: a gem is abandoned when its
    # last release was over 3 years ago (the :critical tier), regardless of
    # commit churn. ~4 years sits comfortably past the 3-year line.
    let(:ancient_release) { Time.now - (4 * 365 * 24 * 60 * 60) }

    it("fires when the last release is over 3 years old, reporting the release gap") do
      report = { "abandoned_gem" => { version_used: "2.0.0", archived: false, latest_version_release_date: ancient_release } }
      results = render(result: report).dig("runs", 0, "results")
      sa002 = results.select { |r| r["ruleId"] == "SA002" }
      expect(sa002.size).to(eq(1))
      expect(sa002[0]["level"]).to(eq("warning"))
      expect(sa002[0].dig("message", "text")).to(match(/no release in [\d.]+ years/))
    end

    it("fires on a stale release even when commits are recent (commit churn does not rescue it)") do
      # The unification bug this fixes: SARIF previously keyed on commit date, so
      # a gem with a fresh commit but a years-old release slipped through.
      report = {
        "abandoned_gem" => {
          version_used: "2.0.0",
          archived: false,
          latest_version_release_date: ancient_release,
          last_commit_date: Time.now,
        },
      }
      results = render(result: report).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA002" }).to(be(true))
    end

    it("falls back to the commit date for a gem with no releases (git-sourced)") do
      report = { "git_gem" => { version_used: "1.0.0", archived: false, last_commit_date: ancient_release } }
      results = render(result: report).dig("runs", 0, "results")
      sa002 = results.select { |r| r["ruleId"] == "SA002" }
      expect(sa002.size).to(eq(1))
      expect(sa002[0].dig("message", "text")).to(match(/no commits in [\d.]+ years/))
    end

    it("does NOT fire when the gem is also archived (SA001 dominates)") do
      report = { "abandoned_gem" => { version_used: "2.0.0", archived: true, latest_version_release_date: ancient_release } }
      results = render(result: report).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA002" }).to(be(false))
      expect(results.any? { |r| r["ruleId"] == "SA001" }).to(be(true))
    end
  end

  describe("SA008 PoisonPill") do
    def poison(constraints, extra = {})
      { "gem" => { version_used: "1.1.4", poison: true, constraints: constraints }.merge(extra) }
    end

    let(:cap) { { dependency: "activemodel", requirement: "< 5.0", dep_latest: "8.0.1", majors_behind: 4, kind: :ceiling } }

    it("fires a warning-level SA008 with the receipt (requirement + exact latest version)") do
      results = render(result: poison([cap])).dig("runs", 0, "results")
      sa008 = results.select { |r| r["ruleId"] == "SA008" }
      expect(sa008.size).to(eq(1))
      expect(sa008[0]["level"]).to(eq("warning"))
      expect(sa008[0].dig("message", "text")).to(include("caps activemodel < 5.0 (4 majors behind, latest 8.0.1)"))
    end

    it("carries no security-severity (maintenance finding, not a CVE)") do
      sa008 = render(result: poison([cap])).dig("runs", 0, "results").find { |r| r["ruleId"] == "SA008" }
      expect(sa008).not_to(have_key("properties"))
    end

    it("fingerprints on gem identity, NOT on majors_behind, so a growing cap is not re-alerted every run") do
      fp = lambda do |behind|
        r = render(result: poison([cap.merge(majors_behind: behind)])).dig("runs", 0, "results").find { |x| x["ruleId"] == "SA008" }
        r.dig("partialFingerprints", "stillActiveFinding/v1")
      end
      expect(fp.call(4)).to(eq(fp.call(5)))
    end

    it("shows the worst 3 caps + more for a many-cap gem") do
      caps = [
        { dependency: "chalk", requirement: "^1", dep_latest: "5.0.0", majors_behind: 4, kind: :ceiling },
        { dependency: "through2", requirement: "^2", dep_latest: "5.0.0", majors_behind: 3, kind: :ceiling },
        { dependency: "vinyl", requirement: "^0.5", dep_latest: "3.0.0", majors_behind: 3, kind: :ceiling },
        { dependency: "dateformat", requirement: "^2", dep_latest: "5.0.0", majors_behind: 3, kind: :ceiling },
      ]
      msg = render(result: poison(caps)).dig("runs", 0, "results").find { |r| r["ruleId"] == "SA008" }.dig("message", "text")
      expect(msg).to(include("+1 more"))
      expect(msg).to(include("chalk ^1 (4 majors behind, latest 5.0.0)"))
    end

    it("names the direct parent for a transitive pill") do
      data = poison([cap], { direct: false, dependency_path: ["rails", "gem"] })
      msg = render(result: data).dig("runs", 0, "results").find { |r| r["ruleId"] == "SA008" }.dig("message", "text")
      expect(msg).to(include("transitive, pulled in by rails"))
    end

    it("does not fire for a non-poison gem or a poison gem with empty constraints") do
      results = render(result: {
        "clean" => { version_used: "1.0.0", poison: false },
        "empty" => { version_used: "1.0.0", poison: true, constraints: [] },
      }).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA008" }).to(be(false))
    end

    it("is suppressible via the :poison signal") do
      StillActive.config.suppressions = StillActive::Suppressions.from(
        [{ "gem" => "gem", "signal" => "poison", "reason" => "vendored" }],
      )
      sa008 = render(result: poison([cap])).dig("runs", 0, "results").find { |r| r["ruleId"] == "SA008" }
      expect(sa008["suppressions"]).to(eq([{ "kind" => "external", "justification" => "vendored" }]))
    end

    it("does NOT fire on a recent release") do
      report = { "fresh_gem" => { version_used: "2.0.0", archived: false, latest_version_release_date: Time.now } }
      results = render(result: report).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA002" }).to(be(false))
    end

    it("does NOT fire on a stale-but-not-critical release (18mo-3yr stays terminal-only)") do
      report = { "stale_gem" => { version_used: "2.0.0", archived: false, latest_version_release_date: Time.now - (2 * 365 * 24 * 60 * 60) } }
      results = render(result: report).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA002" }).to(be(false))
    end
  end

  describe("SA003 VulnerableGem") do
    subject(:results) { render(result: report).dig("runs", 0, "results") }

    let(:report) do
      {
        "vuln_gem" => {
          version_used: "3.0.0",
          vulnerabilities: [
            { id: "CVE-2026-0001", title: "Critical RCE", cvss3_score: 9.1, aliases: ["GHSA-aaaa-bbbb-cccc"] },
            { id: "CVE-2026-0002", title: "Medium DoS", cvss3_score: 5.0 },
          ],
        },
      }
    end

    it("emits one result per advisory") do
      sa003 = results.select { |r| r["ruleId"] == "SA003" }
      expect(sa003.size).to(eq(2))
    end

    it("maps CVSS to level (>= 7 -> error, 4-6.9 -> warning)") do
      sa003 = results.select { |r| r["ruleId"] == "SA003" }
      by_message = sa003.to_h { |r| [r["message"]["text"][/CVE-\d{4}-\d+/], r["level"]] }
      expect(by_message["CVE-2026-0001"]).to(eq("error"))
      expect(by_message["CVE-2026-0002"]).to(eq("warning"))
    end

    it("attaches per-result security-severity from CVSS") do
      sa003 = results.select { |r| r["ruleId"] == "SA003" }
      severities = sa003.map { |r| r.dig("properties", "security-severity") }
      expect(severities).to(contain_exactly("9.1", "5.0"))
    end

    it("uses advisory id in the fingerprint so distinct CVEs get distinct alerts") do
      sa003 = results.select { |r| r["ruleId"] == "SA003" }
      fps = sa003.map { |r| r.dig("partialFingerprints", "stillActiveFinding/v1") }
      expect(fps.uniq.size).to(eq(2))
    end

    it("falls back to cvss2_score when cvss3_score is nil") do
      report_v2 = {
        "vuln_gem" => {
          version_used: "3.0.0",
          vulnerabilities: [{ id: "CVE-old", title: "Older advisory", cvss3_score: nil, cvss2_score: 6.0 }],
        },
      }
      sa003 = render(result: report_v2).dig("runs", 0, "results")
      expect(sa003.size).to(eq(1))
      expect(sa003[0]["level"]).to(eq("warning"))
      expect(sa003[0].dig("properties", "security-severity")).to(eq("6.0"))
    end

    it("emits no security-severity property when both CVSS scores are nil") do
      report_v2 = {
        "vuln_gem" => {
          version_used: "3.0.0",
          vulnerabilities: [{ id: "CVE-unscored", title: "Unscored", cvss3_score: nil, cvss2_score: nil }],
        },
      }
      sa003 = render(result: report_v2).dig("runs", 0, "results", 0)
      expect(sa003["level"]).to(eq("note"))
      expect(sa003["properties"]&.dig("security-severity")).to(be_nil)
    end
  end

  describe("SA004 LibyearBehind") do
    it("fires when libyear exceeds 1.0") do
      report = { "behind_gem" => { version_used: "1.5.0", libyear: 2.5, latest_version: "3.0.0" } }
      results = render(result: report).dig("runs", 0, "results")
      sa004 = results.select { |r| r["ruleId"] == "SA004" }
      expect(sa004.size).to(eq(1))
      expect(sa004[0]["level"]).to(eq("warning"))
    end

    it("does not fire at libyear <= 1.0") do
      report = { "fresh_gem" => { version_used: "1.5.0", libyear: 0.8 } }
      results = render(result: report).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA004" }).to(be(false))
    end
  end

  describe("SA005 LowOpenSSFScore") do
    it("fires when scorecard_score is below 4.0") do
      report = { "weak_gem" => { version_used: "0.5.0", scorecard_score: 2.5 } }
      results = render(result: report).dig("runs", 0, "results")
      sa005 = results.select { |r| r["ruleId"] == "SA005" }
      expect(sa005.size).to(eq(1))
      expect(sa005[0]["level"]).to(eq("note"))
    end

    it("does not fire when scorecard is nil") do
      report = { "unknown_gem" => { version_used: "1.0.0", scorecard_score: nil } }
      results = render(result: report).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA005" }).to(be(false))
    end
  end

  describe("SA006 RubyEOL") do
    it("fires once when ruby_info indicates EOL") do
      ruby_info = { version: "2.7.8", eol: true, eol_date: "2023-03-31T00:00:00Z", latest_version: "3.4.0" }
      results = render(result: {}, ruby_info: ruby_info).dig("runs", 0, "results")
      sa006 = results.select { |r| r["ruleId"] == "SA006" }
      expect(sa006.size).to(eq(1))
      expect(sa006[0]["level"]).to(eq("error"))
      expect(sa006[0]["message"]["text"]).to(include("2.7.8"))
    end

    it("does not fire when ruby is not EOL") do
      ruby_info = { version: "3.4.0", eol: false }
      results = render(result: {}, ruby_info: ruby_info).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA006" }).to(be(false))
    end

    it("does not fire when ruby_info is nil") do
      results = render(result: {}, ruby_info: nil).dig("runs", 0, "results")
      expect(results.any? { |r| r["ruleId"] == "SA006" }).to(be(false))
    end
  end

  describe("SA007 YankedVersion") do
    it("fires when version_yanked is true") do
      report = { "yanked_gem" => { version_used: "4.0.0", version_yanked: true } }
      results = render(result: report).dig("runs", 0, "results")
      sa007 = results.select { |r| r["ruleId"] == "SA007" }
      expect(sa007.size).to(eq(1))
      expect(sa007[0]["level"]).to(eq("error"))
    end
  end

  describe("schema validation") do
    it("validates against the SARIF 2.1.0 JSON schema") do
      ruby_info = { version: "2.7.8", eol: true, latest_version: "3.4.0" }
      report = {
        "archived_gem" => { version_used: "1.0.0", archived: true },
        "abandoned_gem" => { version_used: "2.0.0", archived: false, last_commit_date: (Time.now - (3 * 365 * 24 * 60 * 60)).iso8601 },
        "vuln_gem" => { version_used: "3.0.0", vulnerabilities: [{ id: "CVE-1", cvss3_score: 9.0 }] },
        "behind_gem" => { version_used: "1.5.0", libyear: 2.5 },
        "weak_gem" => { version_used: "0.5.0", scorecard_score: 2.5 },
        "yanked_gem" => { version_used: "4.0.0", version_yanked: true },
      }
      json_str = described_class.render(
        result: report,
        ruby_info: ruby_info,
        lockfile_path: lockfile_path,
        tool_version: tool_version,
      )
      schemer = JSONSchemer.schema(Pathname.new(schema_path))
      errors = schemer.validate(JSON.parse(json_str)).to_a
      expect(errors).to(be_empty, -> { errors.first(3).map { |e| "#{e["data_pointer"]}: #{e["error"]}" }.join("\n") })
    end
  end
end
