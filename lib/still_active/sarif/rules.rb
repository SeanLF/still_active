# frozen_string_literal: true

module StillActive
  module Sarif
    # Catalog of SARIF rules emitted by still_active. Rule IDs (SA001-SA009)
    # are stable across versions; renames or removals are breaking changes.
    #
    # Each rule maps a still_active finding into a SARIF result. Security
    # rules carry a numeric `security_severity` (string per SARIF spec) so
    # GitHub Code Scanning buckets them as Critical/High/Medium/Low.
    module Rules
      extend self

      DOCS_BASE = "https://github.com/SeanLF/still_active/blob/main/docs/rules.md"

      def help_uri(rule_id)
        "#{DOCS_BASE}##{rule_id.downcase}"
      end

      def severity_to_level(label)
        # Maps a resolved advisory severity label (VulnerabilityHelper.advisory_severity:
        # a real CVSS score OR the OSV/GHSA label) to a SARIF level. A nil label is a
        # confirmed-but-unscored advisory (no CVSS score and no OSV label, e.g. a fresh
        # CVE) -- elevated to warning, not an informational note, so a gate can't read
        # it as clean. This is the SARIF analogue of the CLI gate's fail-closed.
        case label
        when "critical", "high" then "error"
        when "medium" then "warning"
        when "low" then "note"
        else "warning"
        end
      end

      # SARIF security-severity must be a string with one decimal place.
      def cvss_to_security_severity(score)
        return if score.nil?

        format("%.1f", score)
      end

      RAW_RULES = [
        {
          id: "SA001",
          name: "ArchivedRepository",
          short: "Gem source repository is archived",
          full: "The gem's upstream repository has been marked archived. No further fixes — including security patches — should be expected.",
          help_text: "Look for a maintained fork or alternative. If you must keep the gem, vendor or fork it so you can apply patches yourself.",
          level: "error",
          security_severity: "7.5",
          tags: ["security", "supply-chain", "external/cwe/cwe-1357"],
        },
        {
          id: "SA002",
          name: "AbandonedGem",
          short: "Gem has had no release for over 3 years",
          full: "The gem's latest release is over 3 years old. Not formally archived, but a strong abandonment signal: a consumer cannot pull fixes that were never released. For a gem with no releases at all (e.g. git-sourced), the last commit date is used instead.",
          help_text: "Verify the gem still works on supported Ruby versions and consider a maintained alternative.",
          level: "warning",
          security_severity: nil,
          tags: ["maintenance"],
        },
        {
          id: "SA003",
          name: "VulnerableGem",
          short: "Gem has known vulnerabilities (via deps.dev / OSV)",
          full: "deps.dev / OSV reports one or more advisories affecting the resolved version. Severity is mapped from CVSS where available.",
          help_text: "Upgrade to a patched version. If no fix exists, evaluate the exploit path against your application's exposure.",
          level: "error",
          security_severity: "7.0", # default; per-result override from CVSS
          tags: ["security", "vulnerability", "external/cwe/cwe-1104"],
        },
        {
          id: "SA004",
          name: "LibyearBehind",
          short: "Gem is significantly behind the latest release",
          full: "Libyear measures how far behind the latest release a dependency is, in fractional years. High libyear values correlate with painful upgrades and missed security backports.",
          help_text: "Schedule an upgrade. `bundle update <gem>` is your friend.",
          level: "warning",
          security_severity: nil,
          tags: ["maintenance", "libyear"],
        },
        {
          id: "SA005",
          name: "LowOpenSSFScore",
          short: "Gem's OpenSSF Scorecard is low",
          full: "The OpenSSF Scorecard aggregates supply-chain hygiene signals. Low scores indicate weak supply-chain posture, not active vulnerability.",
          help_text: "Treat as a risk signal, especially for direct dependencies.",
          level: "note",
          security_severity: nil,
          tags: ["supply-chain", "openssf"],
        },
        {
          id: "SA006",
          name: "RubyEOL",
          short: "Ruby runtime has reached end-of-life",
          full: "The Ruby version in Gemfile.lock is past its endoflife.date EOL — no further security releases are expected.",
          help_text: "Upgrade Ruby. Stay on a release branch still receiving patches.",
          level: "error",
          security_severity: "8.5",
          tags: ["security", "runtime", "external/cwe/cwe-1104"],
        },
        {
          id: "SA007",
          name: "YankedVersion",
          short: "Resolved gem version has been yanked from RubyGems",
          full: "The version resolved in Gemfile.lock has been yanked by the gem owner, typically for a serious bug or vulnerability.",
          help_text: "Update Gemfile.lock to a non-yanked version immediately.",
          level: "error",
          security_severity: "8.0",
          tags: ["security", "supply-chain", "external/cwe/cwe-1104"],
        },
        {
          id: "SA008",
          name: "PoisonPill",
          short: "Dormant gem caps a dependency below its latest major",
          full: "A dormant (abandoned or archived) gem declares a runtime constraint that caps one of its dependencies below that dependency's current latest major. Because nobody is shipping the gem, the cap will never lift, and it grows more constraining as the capped dependency releases new majors: the tree is held below a ceiling no upstream release will raise.",
          help_text: "Replace or fork the dormant gem, or vendor a version that relaxes the constraint. For a transitive pill, target the direct dependency that pulls it in.",
          level: "warning",
          security_severity: nil, # maintenance/resolvability, not a CVE (as SA002/SA004/SA005)
          tags: ["maintenance", "supply-chain", "external/cwe/cwe-1104"],
        },
        {
          id: "SA009",
          name: "RuntimeCeiling",
          short: "Resolved package version caps its language runtime",
          full: "A resolved package version's declared runtime constraint (Ruby `ruby_version`, Python `requires_python`) caps the language runtime you can run: either below every still-supported release (stranding you on an end-of-life runtime with no security patches) or below the latest stable (a compatibility ceiling to plan around). The default level is note; an EOL-forcing cap is raised to error per result.",
          help_text: "If a newer release of the package lifts the cap, upgrade it. Otherwise replace or fork the package, or contribute support for the newer runtime upstream.",
          level: "note",
          security_severity: nil, # maintenance/compatibility, not a CVE (as SA002/SA004/SA005/SA008)
          tags: ["maintenance", "runtime", "external/cwe/cwe-1104"],
        },
      ].freeze

      CATALOG = RAW_RULES.map do |r|
        r.merge(
          tags: r[:tags].dup.freeze,
          help_markdown: "#{r[:help_text]}\n\nSee [#{r[:id]} docs](#{help_uri(r[:id])}) for full guidance.",
        ).freeze
      end.freeze

      def all
        CATALOG
      end

      def find(id)
        CATALOG.find { |r| r[:id] == id }
      end
    end
  end
end
