# frozen_string_literal: true

require_relative "../helpers/vulnerability_helper"
require_relative "../helpers/constraint_helper"
require_relative "../helpers/semver_satisfaction"

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
      advisories = flat_advisories(result_object)
      copies = copy_index(result_object)

      result_object.each_value do |data|
        # FLAT (rubygems/pypi): mark below-fix on the poison caps already attached.
        mark_flat_constraints(data, advisories)
        # NESTED (npm/cargo): promote a genuine below-fix candidate into :constraints.
        promote_nested_below_fix(data, copies) if data[:capped_deps]

        constraints = hashes(data[:constraints])
        next if constraints.empty?

        data[:poison_security_relevant] = true if constraints.any? { |c| c[:capped_dep_vulnerable] }
        data[:poison_below_fix] = true if constraints.any? { |c| c[:capped_below_fix] }
      end
    end

    private

    # This runs OUTSIDE the per-gem rescue (a whole-tree pass after the barrier),
    # so a malformed shape must degrade that one entry's enrichment, never raise and
    # crash the audit after every fetch is paid for. The pipeline always assigns
    # arrays of hashes here, so these guards are unreachable today, but they match the
    # defensive Array()-wrapping the sibling consumers (markdown/sarif/terminal) apply.
    def hashes(value)
      Array(value).grep(Hash)
    end

    # Ecosystem-qualified map of each tree package's advisories AND the version it's
    # pinned at, for the FLAT path (one resolved version per name). A capped dep
    # resolves in its capper's ecosystem, so match "ecosystem/name" on both sides;
    # native results carry no :ecosystem (nil on both) and still match. The used
    # version is kept so "below the fix" ignores fixes that land BELOW it: an OSV
    # advisory lists a fix per affected range, and a fix for an older line is a
    # downgrade, not a patch for the version in hand.
    def flat_advisories(result_object)
      result_object.each_with_object({}) do |(key, data), map|
        next unless data[:vulnerability_count].to_i.positive?

        name = data[:name] || key
        map["#{data[:ecosystem]}/#{name}"] = {vulns: hashes(data[:vulnerabilities]), used_version: data[:version_used]}
      end
    end

    # Every RESOLVED copy of each package, keyed "ecosystem/name", for the NESTED
    # path: npm nests versions and cargo coexists majors, so one name maps to several
    # copies. The full set (vulnerable AND not) is what the condition-5 soundness
    # guard needs -- "is there a SAFE copy within the cap" can't be answered from the
    # vulnerable copies alone.
    def copy_index(result_object)
      result_object.each_with_object({}) do |(key, data), map|
        name = data[:name] || key
        (map["#{data[:ecosystem]}/#{name}"] ||= []) << {version: data[:version_used], vulns: hashes(data[:vulnerabilities])}
      end
    end

    def mark_flat_constraints(data, advisories)
      constraints = hashes(data[:constraints])
      return if constraints.empty?

      eco = data[:ecosystem]
      constraints.each do |constraint|
        entry = advisories["#{eco}/#{constraint[:dependency]}"]
        next if entry.nil?

        vulns = entry[:vulns]
        next unless VulnerabilityHelper.severity_at_or_above?(vulns, SECURITY_THRESHOLD)

        constraint[:capped_dep_vulnerable] = true
        mark_below_fix(constraint, vulns, entry[:used_version])
      end
    end

    # NESTED below-the-fix (npm/cargo). The pure poison cap is suppressed for these
    # ecosystems (caret default + nested copies over-claim), so a candidate is
    # promoted ONLY when it genuinely holds a vulnerable copy below its fix, checked
    # at PATCH precision. When one is, it takes the same shape the flat path renders,
    # and :poison is set here (the only npm/cargo poison there is is a below-fix).
    def promote_nested_below_fix(data, copies)
      eco = data[:ecosystem]
      # Consume the candidates: they are an internal work-list, never serialized.
      promoted = hashes(data.delete(:capped_deps)).filter_map do |candidate|
        dep_copies = copies["#{eco}/#{candidate[:dependency]}"] || []
        nested_below_fix(eco, candidate[:dependency], candidate[:requirement], dep_copies)
      end
      return if promoted.empty?

      data[:constraints] = promoted
      data[:poison] = true
      data[:poison_severity] = :critical
    end

    # A below-fix finding for one capped dep, or nil. The claim holds only when
    # EVERY resolved copy the constraint governs is vulnerable to the same HIGH+
    # advisory (condition 5: no safe in-constraint copy to resolve to), AND no fix
    # of that advisory satisfies the constraint (the wall, at patch precision). A
    # patched copy sitting OUTSIDE the constraint elsewhere in the tree is irrelevant
    # -- it can't lift the copy this capper pins -- so it never enters this view.
    def nested_below_fix(ecosystem, dependency, requirement, dep_copies)
      in_constraint = dep_copies.select { |copy| satisfies?(requirement, copy[:version], ecosystem) }
      return if in_constraint.empty?

      oldest = in_constraint.map { |copy| copy[:version] }.min_by { |version| gem_version(version) }
      stuck = candidate_advisories(in_constraint).select do |advisory|
        walls?(requirement, advisory, ecosystem, oldest) && every_copy_affected?(in_constraint, advisory)
      end
      return if stuck.empty?

      receipt = stuck.min_by { |advisory| gem_version(nearest_fix(advisory, oldest)) }
      {
        dependency: dependency,
        requirement: requirement,
        capped_dep_vulnerable: true,
        capped_below_fix: true,
        below_fix_advisory: receipt[:id],
        below_fix_fixed_in: nearest_fix(receipt, oldest)
      }
    end

    def satisfies?(requirement, version, ecosystem)
      SemverSatisfaction.evaluate(requirement: requirement, version: version, ecosystem: ecosystem) == true
    end

    # HIGH+ advisories with a known fix, deduped by id, across the in-constraint copies.
    def candidate_advisories(copies)
      copies.flat_map { |copy| copy[:vulns] }
        .select { |vuln| BELOW_FIX_LABELS.include?(VulnerabilityHelper.advisory_severity(vuln)) && Array(vuln[:fixed_versions]).any? }
        .uniq { |vuln| vuln[:id] }
    end

    # The wall: NO applicable fix satisfies the constraint at patch precision. Every
    # fix must be a DEFINITE non-match (evaluate == false); an undecidable fix (nil,
    # unparseable) blocks the claim rather than counting as unreachable, so we never
    # fabricate a wall from input we couldn't parse.
    def walls?(requirement, advisory, ecosystem, oldest_affected)
      fixes = applicable_fixes(advisory, oldest_affected)
      fixes.any? && fixes.all? { |fix| SemverSatisfaction.evaluate(requirement: requirement, version: fix, ecosystem: ecosystem) == false }
    end

    # Condition 5: every governed copy is vulnerable to THIS advisory (none is a safe
    # version you could resolve to within the cap).
    def every_copy_affected?(copies, advisory)
      copies.all? { |copy| copy[:vulns].any? { |vuln| vuln[:id] == advisory[:id] } }
    end

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
