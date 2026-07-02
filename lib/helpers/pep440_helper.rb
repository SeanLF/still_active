# frozen_string_literal: true

module StillActive
  # Translates a PEP 440 `requires_python` specifier into a RubyGems requirement
  # STRING, so the generic RuntimeCeilingHelper can reason about a Python runtime
  # ceiling with no core change -- the same way Ruby's `ruby_version` already
  # feeds it. PEP 440 and RubyGems disagree on two operators that matter here:
  #
  #   - `~=` (compatible release) is a syntax error to Gem::Requirement, so a
  #     naive parse raises and the ceiling is silently missed. It maps cleanly to
  #     RubyGems `~>` for the major.minor.patch shapes `requires_python` uses.
  #   - `== X.*` / `== X.Y.*` prefix wildcards are likewise unparseable and map to
  #     a pessimistic `~>` over the prefix.
  #
  # `!=` exclusions are dropped: a hole-punch can never create an upper bound, so
  # it cannot be a runtime ceiling, and dropping it can only ADMIT more runtimes
  # (fewer findings) -- conservative, never a false ceiling. Anything that still
  # won't parse degrades to a dropped clause (or nil overall), never a raise: this
  # feeds the core audit and must fail safe, matching RuntimeCeilingHelper's
  # best-effort contract.
  module Pep440Helper
    extend self

    # Match ConstraintHelper / RuntimeCeilingHelper: bound pathological registry
    # input before it reaches Gem::Requirement's own regex.
    MAX_SPECIFIER_LENGTH = 256

    # Operator, then the version as a run of non-space chars. `\s*(\S+)` (not
    # `\s*(.+)`) keeps the two groups over disjoint character classes so there's no
    # polynomial backtracking on pathological input like "<" + many spaces (a PEP
    # 440 version never contains internal spaces, so this loses nothing).
    CLAUSE_PATTERN = /\A(===|==|~=|!=|<=|>=|<|>)\s*(\S+)\z/

    # => a comma-joined RubyGems requirement string, or nil when nothing usable
    # survives translation. The caller feeds the string to RuntimeCeilingHelper,
    # which splits and splats it exactly like a `ruby_version` string.
    def to_gem_requirement_string(specifier)
      spec = specifier.to_s
      return if spec.strip.empty? || spec.length > MAX_SPECIFIER_LENGTH

      clauses = spec.split(",").filter_map { |clause| translate_clause(clause.strip) }
      return if clauses.empty?

      clauses.join(", ")
    end

    private

    def translate_clause(clause)
      match = CLAUSE_PATTERN.match(clause)
      return if match.nil?

      operator = match[1]
      version = match[2].strip

      case operator
      when "!=" then nil # hole-punch: never an upper bound, drop it
      when "~=" then compatible_release(version)
      when "==", "===" then equality(version)
      else comparison(operator, version)
      end
    end

    # `~= X.Y[.Z]` is `>= X.Y[.Z], == X.Y.*` which is exactly RubyGems `~> X.Y[.Z]`.
    def compatible_release(version)
      return unless parseable?(version)

      "~> #{version}"
    end

    def equality(version)
      if version.end_with?(".*")
        prefix_match(version.delete_suffix(".*"))
      elsif parseable?(version)
        "= #{version}"
      end
    end

    # `== P.*` matches every release whose version starts with prefix P, i.e.
    # `>= P, < P-with-last-segment-incremented`. RubyGems spells that as `~> P.0`
    # (append one segment so the pessimistic bump lands on P's last segment):
    #   ==3.*   -> ~> 3.0   (>=3, <4)
    #   ==3.7.* -> ~> 3.7.0 (>=3.7, <3.8)
    def prefix_match(prefix)
      return unless parseable?(prefix)

      "~> #{prefix}.0"
    end

    def comparison(operator, version)
      return unless parseable?(version)

      "#{operator} #{version}"
    end

    def parseable?(version)
      Gem::Version.correct?(version)
    end
  end
end
