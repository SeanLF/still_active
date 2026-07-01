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

    # An exact pin: = / == / === before a digit (NOT >= or <=).
    EXACT_PIN = /\A={1,3}\s*v?\d/
    # A bare version with no operator (npm/cargo exact form), e.g. "1.2.3", "v1".
    BARE_VERSION = /\Av?\d+(?:\.\d+)*\z/
    # Operator + version at the head of a clause.
    CLAUSE = /\A(===?|=|<=|<|~>|~=|\^|~)?\s*v?(\d+(?:\.\d+)*)/
    # Whitespace that separates npm AND clauses (">=1.2.0 <2.0.0"), i.e. a space
    # before an operator. It won't split a Ruby clause like "~> 4.2" (the space
    # there precedes a digit, not an operator).
    AND_SEPARATOR = /\s+(?=[<>=~^])/

    # => { kind: :permissive|:ceiling|:exact_pin, majors_behind: Integer }
    def analyze(requirement:, dep_latest:)
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

    # The poison condition: a below-latest ceiling or exact pin. A permissive
    # constraint, or a cap at/above the dep's latest major, is not a pill.
    def poison_ceiling?(requirement:, dep_latest:)
      result = analyze(requirement: requirement, dep_latest: dep_latest)
      [:ceiling, :exact_pin].include?(result[:kind]) && result[:majors_behind].positive?
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
