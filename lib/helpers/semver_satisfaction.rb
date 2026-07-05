# frozen_string_literal: true

require "semantic_range"

module StillActive
  # Does a concrete version satisfy a declared requirement, at PATCH precision,
  # for npm and cargo? This is the primitive the cross-ecosystem below-the-fix
  # signal needs: a CVE's fix is usually a same-major patch bump, so "can this fix
  # be reached within the package's constraint" cannot be answered by the coarse,
  # major-precision ConstraintHelper. node-semver's caret/tilde/OR/prerelease rules
  # are a correctness minefield, so we lean on the semantic_range gem (a node-semver
  # port) rather than reimplement them.
  #
  # npm ranges are node-semver as-is. cargo's VersionReq agrees with node-semver on
  # every operator form AND on partial bare versions (`1`, `1.2`), diverging in ONE
  # place: a bare FULL version (`1.2.3`) is an exact pin in npm but a caret in cargo
  # (`^1.2.3`). That single rule is the whole cargo shim; getting it wrong would
  # read a reachable same-minor fix as unreachable and fabricate a security finding.
  module SemverSatisfaction
    extend self

    # A bare full version with no leading operator: `1.2.3`, `0.10.38`, optionally a
    # prerelease and/or build tail (`1.2.3-alpha+001`). Cargo reads this as a caret;
    # npm as an exact pin.
    BARE_FULL_VERSION = /\A\s*v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\s*\z/

    # Does `version` satisfy `requirement`? true / false when decidable; nil when the
    # requirement or version isn't valid semver for the ecosystem, or the ecosystem
    # isn't one we model. The tri-state is deliberate (hence a plain verb, not a
    # `?` predicate): semantic_range returns false for garbage, and a false would read
    # as "the fix can't be reached" in a wall test and fabricate a below-the-fix flag.
    # The caller must treat nil as "cannot establish a wall", never as unreachable.
    def evaluate(requirement:, version:, ecosystem:)
      range = range_for(requirement, ecosystem)
      return if range.nil? # undecidable: unmodelled ecosystem or unparseable requirement
      return if SemanticRange.valid(version.to_s).nil? # undecidable: unparseable version

      SemanticRange.satisfies?(version.to_s, range)
    end

    private

    # The node-semver range string for this ecosystem's requirement, or nil if it
    # isn't a valid range (or the ecosystem is unmodelled). cargo's bare-full-version
    # caret is applied BEFORE validation so the shimmed form is what gets checked.
    def range_for(requirement, ecosystem)
      requirement = requirement.to_s.strip
      # A blank requirement is missing data (a failed extraction), NOT a package that
      # allows any version: semantic_range reads "" as `*` (matches everything), which
      # would be a false-confident answer. Keep it undecidable, like a blank version.
      return if requirement.empty?

      case ecosystem
      when :npm then SemanticRange.valid_range(requirement)
      when :cargo then SemanticRange.valid_range(cargo_normalize(requirement))
      end
    end

    # `requirement` arrives already stripped from range_for.
    def cargo_normalize(requirement)
      requirement.match?(BARE_FULL_VERSION) ? "^#{requirement}" : requirement
    end
  end
end
