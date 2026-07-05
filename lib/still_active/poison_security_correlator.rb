# frozen_string_literal: true

require_relative "../helpers/vulnerability_helper"
require_relative "../helpers/constraint_helper"

module StillActive
  # Whole-tree correlation, run once after the fan-out: a poison cap is far more
  # urgent when the dependency it pins is ITSELF vulnerable in the same tree --
  # "a dormant package is holding you on a known-vulnerable dependency, below the
  # version that fixes it." Both facts are already assembled (the poison
  # constraints and every dependency's vulnerability count), so this is one pass,
  # no extra fetches. It marks the security-relevant caps so the report can lead
  # with them and demote the FYI caps on healthy dependencies.
  #
  # The moat's strongest case (verified on real repos): several archived Google
  # client libraries pin a vulnerable `protobuf` three majors below the fix.
  module PoisonSecurityCorrelator
    extend self

    # Only a HIGH-or-above advisory on the capped dep makes the cap security-
    # relevant. Most advisories are low-threat noise (research: ~95% of vulnerable
    # deps are unreachable/low-impact), so a low/medium CVE on the pinned dep isn't
    # the "you're stuck below the fix" story. Unscored advisories fail CLOSED (a
    # confirmed advisory we can't score could be severe), matching --fail-if-
    # vulnerable. Reachability/exploitability is beyond static, metadata-only sight
    # and deliberately out of scope -- this gates on severity, not exploitability.
    SECURITY_THRESHOLD = "high"

    # The severity labels that let an advisory establish "below the fix". Only a
    # confirmed HIGH+ advisory with a known fix can: an unscored advisory (which the
    # capped_dep_vulnerable gate accepts fail-closed) has no reliable fix analysis.
    BELOW_FIX_LABELS = ["high", "critical"].freeze

    def correlate(result_object)
      # Ecosystem-qualified map of each tree package's advisories AND the version
      # it's pinned at. A capped dep resolves in its capper's ecosystem, so match
      # "ecosystem/name" on both sides; native results carry no :ecosystem (nil on
      # both) and still match. The used version is kept so "below the fix" ignores
      # fixes that land BELOW it: an OSV advisory lists a fix per affected range, and
      # a fix for an older line is a downgrade, not a patch for the version in hand.
      advisories = result_object.each_with_object({}) do |(key, data), map|
        next unless data[:vulnerability_count].to_i.positive?

        name = data[:name] || key
        map["#{data[:ecosystem]}/#{name}"] = { vulns: data[:vulnerabilities] || [], used_version: data[:version_used] }
      end

      result_object.each_value do |data|
        constraints = data[:constraints]
        next if constraints.nil? || constraints.empty?

        eco = data[:ecosystem]
        constraints.each do |constraint|
          entry = advisories["#{eco}/#{constraint[:dependency]}"]
          next if entry.nil?

          vulns = entry[:vulns]
          next unless VulnerabilityHelper.severity_at_or_above?(vulns, SECURITY_THRESHOLD)

          constraint[:capped_dep_vulnerable] = true
          mark_below_fix(constraint, vulns, entry[:used_version])
        end
        data[:poison_security_relevant] = true if constraints.any? { |c| c[:capped_dep_vulnerable] }
        data[:poison_below_fix] = true if constraints.any? { |c| c[:capped_below_fix] }
      end
    end

    private

    # The sharper claim on a security-relevant cap: does it hold you BELOW THE FIX?
    # A HIGH+ advisory with a known fix establishes it only when EVERY fixed version
    # lands outside the cap (a major it forbids) -- you cannot patch the CVE without
    # replacing the dormant capper. The receipt names the advisory and its nearest
    # fix (the lowest fixed version, all of which are outside the cap).
    def mark_below_fix(constraint, vulns, used_version)
      stuck = vulns.select do |vuln|
        fixes = applicable_fixes(vuln, used_version)
        next false if fixes.empty?
        next false unless BELOW_FIX_LABELS.include?(VulnerabilityHelper.advisory_severity(vuln))

        fixes.none? { |fix| ConstraintHelper.reachable_within_cap?(constraint, fix) }
      end
      return if stuck.empty?

      receipt = stuck.min_by { |vuln| gem_version(nearest_fix(vuln, used_version)) }
      constraint[:capped_below_fix] = true
      constraint[:below_fix_advisory] = receipt[:id]
      constraint[:below_fix_fixed_in] = nearest_fix(receipt, used_version)
    end

    # An advisory lists a fixed version per affected range; only fixes ABOVE the
    # version in hand are real remediation. A fix at or below it belongs to an older
    # release line (a downgrade), so it neither patches this version nor counts as
    # "reachable within the cap". With no known used version (older data), all fixes
    # are kept -- the pre-existing behaviour, never fewer findings than before.
    def applicable_fixes(vuln, used_version)
      fixes = Array(vuln[:fixed_versions])
      return fixes if used_version.nil? || !Gem::Version.correct?(used_version.to_s)

      used = gem_version(used_version)
      fixes.select { |fix| !Gem::Version.correct?(fix.to_s) || gem_version(fix) > used }
    end

    # The lowest applicable fixed version, for the "fixed in X" receipt. A parseable
    # version always beats an unparseable one (PyPI epoch `1!2.3.4`, or garbage), so
    # the receipt never names an odd string when a clean fix is present; only when
    # EVERY fix is unparseable does it fall back to one of those.
    def nearest_fix(vuln, used_version)
      applicable_fixes(vuln, used_version).min_by { |fix| [Gem::Version.correct?(fix.to_s) ? 0 : 1, gem_version(fix)] }
    end

    # A version key that sorts fix strings without raising; an unparseable version
    # collapses to 0 (only reached as a tiebreak among all-unparseable fixes, since
    # nearest_fix prefers parseable ones).
    def gem_version(version)
      Gem::Version.new(version.to_s)
    rescue ArgumentError
      Gem::Version.new("0")
    end
  end
end
