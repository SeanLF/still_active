# frozen_string_literal: true

module StillActive
  # Reads a declared dependency constraint (the requirement string a package
  # publishes for one of its runtime deps, e.g. "~> 4.2", "< 5.0", "= 1.2.3") and
  # answers how much it caps you: is there an upper bound, and how many majors
  # behind the dependency's current latest does it hold you?
  #
  # This is the constraint half of the poison-pill signal (constraint-tightness x
  # maintenance-state): a dormant package that caps a still-evolving dep below its
  # latest major holds your tree hostage with no hope of the cap lifting. A fixed
  # cap gets more poisonous purely with time, as the capped dep ships new majors
  # while the cap stays frozen.
  #
  # Grammar is coarse but cross-ecosystem: Ruby pessimistic (~>), pip compatible
  # (~=), semver caret/tilde (^ ~), exact (= == ===), and plain </<=. Precision is
  # at the MAJOR level, which is all the signal needs ("N majors behind").
  module ConstraintHelper
    extend self

    # The constraint kinds that make a dep a poison-pill candidate: an upper bound
    # that blocks upgrades, or an exact pin that freezes the whole tree. A
    # `:permissive` constraint is neither. Shared with the workflow so the poison
    # definition lives in one place.
    POISON_KINDS = [:ceiling, :exact_pin].freeze

    # An exact pin: = / == / === before a digit (NOT >= or <=).
    EXACT_PIN = /\A={1,3}\s*v?\d/
    # A bare version with no operator (npm/cargo exact form), e.g. "1.2.3", "v1".
    BARE_VERSION = /\Av?\d+(?:\.\d+)*\z/
    # Operator + version at the head of a clause.
    CLAUSE = /\A(===?|=|<=|<|~>|~=|\^|~)?\s*v?(\d+(?:\.\d+)*)/
    # Whitespace that separates npm AND clauses (">=1.2.0 <2.0.0"), i.e. a space
    # before an operator. It won't split a Ruby clause like "~> 4.2" (the space
    # there precedes a digit, not an operator). The quantifier is POSSESSIVE
    # (`\s++`, not `\s+`): a lookahead after a greedy `\s+` backtracks once per
    # trailing space, which is quadratic on a long run of spaces (ReDoS on the
    # lockfile-derived requirement string). Possessive matching never backtracks.
    AND_SEPARATOR = /\s++(?=[<>=~^])/
    # A real declared requirement ("< 5.0, >= 4.0.1", "^1 || ^2 || ^3") is short.
    # Anything past this is not a parseable constraint, so cap the input up front:
    # it bounds every regex below to linear work and refuses to mint a pill from
    # garbage (an over-long string reads as permissive, never a false ceiling).
    MAX_REQUIREMENT_LENGTH = 256

    # => { kind: :permissive|:ceiling|:exact_pin, majors_behind: Integer }
    def analyze(requirement:, dep_latest:)
      return { kind: :permissive, majors_behind: 0 } if requirement.to_s.length > MAX_REQUIREMENT_LENGTH

      # `||` is an OR-range (npm): satisfied by ANY branch, so an unbounded branch
      # lifts the cap entirely and the effective ceiling is the LOOSEST branch.
      # Reading only the first branch would invent a false pill on the common
      # `^2.0.0 || ^3.0.0` "supports several majors" form.
      branches = requirement.to_s.split("||").map { |branch| clauses_of(branch) }
      branches = [[]] if branches.empty?
      ceilings = branches.map { |clauses| branch_ceiling(clauses) }
      latest_major = major(dep_latest)

      return { kind: :permissive, majors_behind: 0 } if ceilings.any?(&:nil?)

      behind = latest_major ? [latest_major - ceilings.max, 0].max : 0
      kind = branches.all? { |clauses| all_exact?(clauses) } ? :exact_pin : :ceiling
      { kind: kind, majors_behind: behind }
    end

    # Severity tiers for a compatibility ceiling, worst-last (mirrors
    # StatusHelper::SEVERITY -- an ordinal set compared by index, never a numeric
    # composite). :note is FYI, :warning is review-and-plan, :critical is act-now.
    SEVERITY = [:note, :warning, :critical].freeze

    # Tier one ceiling finding. Magnitude-driven: the real-project dogfood showed
    # Ruby findings are bimodal -- 1 major behind is trivial (a done gem pinning an
    # old minor), 3+ is a genuine upgrade wall (e.g. capping actionmailer below
    # Rails 6). Popularity was rejected as an input (it ranks the framework blocker
    # below a utility) and a vulnerable-gem escalator was rejected (that is the
    # vulnerability finding's job, not the cap's).
    def constraint_severity(finding)
      # A runtime ceiling that strands you on an end-of-life Ruby is act-now: no
      # patched runtime is reachable. This short-circuit lets the language-ceiling
      # signal (which carries no majors_behind) reuse the same tierer as poison.
      return :critical if finding[:eol_forced]

      case finding[:majors_behind]
      when 2 then :warning
      when 3.. then :critical
      else :note
      end
    end

    # The worst tier across a gem's CEILING findings (exact-pins are a milder
    # hazard, not poison, and don't carry a tier), or nil when there are none.
    def worst_severity(findings)
      tiers = findings.filter_map { constraint_severity(_1) if _1[:kind] == :ceiling }
      tiers.max_by { SEVERITY.index(_1) }
    end

    # For the --fail-if-poison[=TIER] gate: is `severity` at or above `threshold`?
    def severity_at_or_above?(severity, threshold)
      return false if severity.nil?

      SEVERITY.index(severity) >= SEVERITY.index(threshold)
    end

    # True when `version` sits at or below the highest major the cap allows -- i.e.
    # you could upgrade the capped dep to it WITHOUT breaking the cap. The ceiling
    # major is recovered from the poison finding itself (dep_latest minus
    # majors_behind), at the same major precision the poison signal already uses, so
    # a fix that lands OUTSIDE the cap ("below the fix") is detected without
    # re-parsing the raw requirement and its pre/dev-release quirks (`< 5.0.0dev`).
    #
    # Precision is MAJOR-level by design, and that errs deliberately toward reachable:
    # a within-major cap (`~> 4.2.1`, `< 5.5`) reads a same-major fix (4.9.0, 5.29.6)
    # as reachable even though the cap forbids it. So a genuinely-stuck within-major
    # cap is UNDER-reported (downgraded to the still-visible "vulnerable" tier), never
    # falsely promoted -- when this DOES return false for every fix, the below-the-fix
    # claim is sound (every fix is in a strictly higher major than the cap allows).
    # Unparseable/absent inputs read false (never claims reachable when we can't tell).
    def reachable_within_cap?(finding, version)
      fix_major = major(version)
      latest_major = major(finding[:dep_latest])
      behind = finding[:majors_behind]
      return false if fix_major.nil? || latest_major.nil? || behind.nil?

      fix_major <= latest_major - behind
    end

    # The poison condition: a below-latest ceiling or exact pin. A permissive
    # constraint, or a cap at/above the dep's latest major, is not a pill.
    def poison_ceiling?(requirement:, dep_latest:)
      result = analyze(requirement: requirement, dep_latest: dep_latest)
      POISON_KINDS.include?(result[:kind]) && result[:majors_behind].positive?
    end

    # Build the poison-pill receipts for a package's declared runtime deps. Each
    # `dep` is { package_name:, requirements: }; the block resolves a dep name to
    # its current latest version string (or nil when unresolvable, which drops the
    # dep rather than guessing). Returns only the below-latest ceilings and exact
    # pins, each as a self-contained receipt. Shared by the native Bundler path and
    # the cross-ecosystem lens, which differ only in how they resolve dep_latest.
    def poison_findings(deps)
      deps.filter_map do |dep|
        dep_latest = yield(dep[:package_name])
        next if dep_latest.nil?

        result = analyze(requirement: dep[:requirements], dep_latest: dep_latest)
        next unless POISON_KINDS.include?(result[:kind]) && result[:majors_behind].positive?

        {
          dependency: dep[:package_name],
          requirement: dep[:requirements],
          dep_latest: dep_latest,
          majors_behind: result[:majors_behind],
          kind: result[:kind],
        }
      end
    end

    # Select the worst `limit` findings for a display receipt, plus the full count
    # so a renderer can say "+N more" / "N total". Worst-first by majors_behind,
    # ties broken by dependency name so the output is stable and diffable. Shared
    # by the terminal and markdown renderers so the selection can't drift.
    def top_findings(findings, limit: 3)
      ranked = findings.sort_by { |f| [-f[:majors_behind], f[:dependency].to_s] }
      { shown: ranked.first(limit), total: findings.length }
    end

    private

    # Split one OR-branch into its AND clauses: comma-separated (Ruby/pip) or
    # space-separated (npm ">=1.2.0 <2.0.0").
    def clauses_of(branch)
      branch.split(",").flat_map { |part| part.strip.split(AND_SEPARATOR) }.map(&:strip).reject(&:empty?)
    end

    # The tightest ceiling major within one AND-branch, or nil when the branch has
    # no upper bound at all (a lone lower bound = permissive, lifts the OR cap).
    def branch_ceiling(clauses)
      clauses.filter_map { |clause| clause_ceiling_major(clause) }.min
    end

    def all_exact?(clauses)
      !clauses.empty? && clauses.all? { |clause| clause.match?(EXACT_PIN) || clause.match?(BARE_VERSION) }
    end

    def clause_ceiling_major(clause)
      match = clause.match(CLAUSE)
      return unless match

      operator = match[1]
      major_of = major(match[2])
      case operator
      # `< X.0.0` excludes major X entirely (max usable major is X-1); `< X.Y`
      # with a non-zero minor still allows major X.
      when "<" then all_zero_after_major?(match[2]) ? major_of - 1 : major_of
      when "<=", "~>", "~=", "^", "~", "=", "==", "===", nil then major_of
      end # `>`/`>=` fall through to nil: a lower bound imposes no ceiling
    end

    def all_zero_after_major?(version)
      version.split(".").drop(1).all? { |part| part.to_i.zero? }
    end

    def major(version)
      digits = version.to_s[/\d+/]
      digits&.to_i
    end
  end
end
