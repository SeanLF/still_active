# frozen_string_literal: true

require_relative "constraint_helper"

module StillActive
  # The language-runtime sibling of the poison-pill signal, kept deliberately
  # generic: it reads a constraint a package declares on its RUNTIME (the version
  # range it can run on) and, given that runtime's support window, answers how much
  # the constraint holds you back. Ruby (`ruby_version`) is the first consumer, but
  # nothing here is Ruby-specific: the same core serves any runtime with an
  # end-of-life calendar (Python's `requires_python`, etc.). The runtime-specific
  # parts -- where the constraint string comes from, and how the support window is
  # built -- live in the calibration layer (RubyHelper.supported_ruby_range) and
  # the workflow boundary, exactly as poison keeps ConstraintHelper generic and
  # pushes ecosystem resolution to the lens.
  #
  # Two tiers, mirroring the severity model:
  #   - EOL-forced (critical): the constraint admits no still-supported runtime,
  #     stranding you on an end-of-life release with no security patches. A genuine
  #     upgrade blocker (e.g. a gem's `ruby_version < 3.2` caps at the EOL Ruby 3.1).
  #   - latest-not-yet (note): runs on a supported runtime but caps below the latest
  #     stable. An FYI ceiling to plan around, or a place to contribute support for
  #     the newest release before you invest.
  #
  # A bare floor (`>= 3.1`) or a requires-newer constraint (`>= 4.1`, `~> 5.0`) is
  # NOT a ceiling: it raises the minimum, it doesn't cap you onto a dead release.
  # The distinction is drawn against the live EOL cycles, not the operator alone.
  module RuntimeCeilingHelper
    extend self

    # Gem::Requirement caps input via a regex; a registry-derived string could be
    # pathological. Bound it up front like ConstraintHelper does.
    MAX_REQUIREMENT_LENGTH = 256

    # => { requirement:, eol_forced:, severity:, ... } or nil when there's no
    # ceiling. `support_window` is a { oldest_supported:, latest_stable:, cycles: }
    # hash of Gem::Versions plus normalized EOL cycles (see supported_ruby_range).
    def analyze(requirement:, support_window:)
      return if support_window.nil?

      req = safe_requirement(requirement)
      return if req.nil? || !capping?(req)

      supported_allowed = support_window[:cycles].reject { |c| c[:eol] }.select { |c| req.satisfied_by?(c[:version]) }

      if supported_allowed.empty?
        eol_forced_finding(req, requirement, support_window)
      elsif !req.satisfied_by?(support_window[:latest_stable]) && !support_window[:latest_stable_fresh]
        # Runs on a supported runtime but not the latest stable. Suppressed while
        # the latest stable is still within its grace window (see supported_ruby_
        # range): right after a runtime ships, "doesn't support it yet" indicts the
        # release calendar, not the gem. After the window it is a real note.
        latest_not_yet_finding(requirement, support_window)
      end
    end

    private

    # A ceiling exists only if the constraint has an upper bound. A pure lower
    # bound (`>`, `>=`) can never strand you on an old release, so skip it before
    # any cycle math (this is also what keeps `>= 4.1` requires-newer out). Exact
    # pins (`=`) are excluded deliberately: pinning a runtime to an exact patch is
    # pathological (unheard of in practice) and can't be matched against the
    # major.minor EOL cycles anyway, so we don't fabricate support for it.
    CAPPING_OPERATORS = ["<", "<=", "~>"].freeze

    def capping?(req)
      req.requirements.any? { |operator, _version| CAPPING_OPERATORS.include?(operator) }
    end

    def eol_forced_finding(req, requirement, support_window)
      # No supported release is admitted. Only a genuine cap (admits some EOL
      # release) is EOL-forced; a requires-newer floor admits nothing at or below
      # the oldest supported and is not our concern.
      allowed_eol = support_window[:cycles].select { |c| c[:eol] && req.satisfied_by?(c[:version]) }
      return if allowed_eol.empty?

      ceiling = allowed_eol.max_by { |c| c[:version] }
      finding = {
        requirement: requirement,
        eol_forced: true,
        ceiling_version: ceiling[:version].to_s,
        ceiling_eol_date: ceiling[:eol_date],
        oldest_supported: support_window[:oldest_supported].to_s,
        latest_stable: support_window[:latest_stable].to_s,
      }
      finding.merge(severity: ConstraintHelper.constraint_severity(finding))
    end

    def latest_not_yet_finding(requirement, support_window)
      finding = {
        requirement: requirement,
        eol_forced: false,
        oldest_supported: support_window[:oldest_supported].to_s,
        latest_stable: support_window[:latest_stable].to_s,
      }
      finding.merge(severity: ConstraintHelper.constraint_severity(finding))
    end

    # Registries render a floor+ceiling requirement as a single comma-joined string
    # (e.g. ">= 2.5, < 3.2" -- common for `ruby_version`/`required_ruby_version`).
    # Gem::Requirement.new can't parse that one-string form (it raises), so split
    # into clauses and splat, preserving BOTH bounds. Reading only the string as-is
    # would drop the `< 3.2` ceiling and silently miss the very case this exists to
    # catch. Best-effort: a genuinely malformed clause degrades to nil (no finding),
    # never a raised exception that could break the core audit.
    def safe_requirement(requirement)
      return if requirement.nil? || requirement.to_s.length > MAX_REQUIREMENT_LENGTH

      clauses = requirement.to_s.split(",").map(&:strip).reject(&:empty?)
      return if clauses.empty?

      Gem::Requirement.new(*clauses)
    rescue ArgumentError
      # Covers Gem::Requirement::BadRequirementError (a subclass) plus any other
      # malformed-input ArgumentError, so a pathological registry string degrades
      # to "no ceiling" and never breaks the core audit.
      nil
    end
  end
end
