# frozen_string_literal: true

require_relative "activity_helper"

module StillActive
  # Collapses a gem's several maintenance signals into one categorical verdict,
  # so a machine/LLM consumer (or another tool's report) can display and threshold
  # a single value instead of re-deriving it from activity_level + archived +
  # vulnerability_count. This is deliberately NOT a numeric composite: an earlier
  # 0-100 score was removed because a weighted average let missing data read as
  # "perfect health". Here, :unknown stays :unknown -- absence of data is never
  # rendered as :ok.
  module StatusHelper
    extend self

    # Worst-first lifecycle verdict. The key distinction (from the "done gems"
    # critique and validated against the maintenance-tooling landscape): a clean,
    # long-dormant gem is :legacy ("done", low risk), NOT a problem -- whereas a
    # dormant or archived gem carrying an unpatched advisory is :dead (no one is
    # going to fix it, migrate). :unknown is least severe -- an absence, not a
    # finding -- so missing data never reads as :ok.
    # :deprecated sits above :archived and below :vulnerable. An archived repo is
    # circumstantial (development may simply have moved), whereas a deprecation is
    # the maintainer explicitly telling you to stop using the package, frequently
    # naming the replacement. A live vulnerability is still the more urgent thing.
    SEVERITY = [:unknown, :ok, :legacy, :stale, :archived, :deprecated, :vulnerable, :dead].freeze

    # Returns :dead, :vulnerable, :deprecated, :archived, :legacy, :stale, :ok,
    # or :unknown.
    def gem_status(gem_data)
      vulnerable = gem_data[:vulnerability_count].to_i.positive?

      # A pinned version the registry can't resolve (yanked, typo, or nonexistent)
      # has no version-specific data to judge, so package-level health must not read
      # it as :ok. Absence of data is :unknown, never a false all-clear. Guarded on
      # `!vulnerable` so a detected advisory always wins, in case a future source
      # ever attaches one to an otherwise-unresolved version.
      return :unknown if gem_data[:version_unresolved] && !vulnerable

      level = ActivityHelper.activity_level(gem_data)
      # The maintainer's own declaration that this package should no longer be
      # used. Unlike every other input here it is a stated fact rather than a date
      # heuristic, so it is read before the activity level rather than blended
      # with it.
      deprecated = gem_data[:deprecated] == true

      if vulnerable
        # A vulnerability in a dormant, archived or deprecated gem won't be patched
        # -> :dead; in an actively-released gem a fix is plausible -> :vulnerable.
        # Deprecation counts even on a gem still shipping releases: the maintainer
        # has said to stop using it, so waiting for the patch is not a plan.
        return (deprecated || [:critical, :archived].include?(level)) ? :dead : :vulnerable
      end

      # Deliberately ahead of the :critical -> :legacy branch below. :legacy means
      # "long-dormant but done, low risk", and a deprecated package is the exact
      # case that must not be filed there: left-pad is dormant AND clean AND its
      # maintainer says to use String.prototype.padStart() instead.
      return :deprecated if deprecated

      case level
      when :archived
        # archived != EOL: a repo archived while the gem still publishes recent
        # releases (development moved to a monorepo) isn't dead -- let the
        # releases speak, but keep :stale so the archived repo stays a yellow flag.
        (ActivityHelper.release_recency_level(gem_data) == :ok) ? :stale : :archived
      when :critical then :legacy # long-dormant but clean: feature-complete, not a fire
      else level # :stale / :ok / :unknown
      end
    end

    # The single worst gem status across the audit. An EOL Ruby floors the
    # project at :vulnerable (the runtime itself is a live, actionable risk).
    # :unknown only wins when nothing better is known.
    def project_status(result, ruby_info: nil)
      statuses = result.each_value.map { |data| gem_status(data) }
      statuses << :vulnerable if ruby_info&.dig(:eol) == true
      return :unknown if statuses.empty?

      # Every value gem_status returns is in SEVERITY today; if a future status
      # isn't, rank it most-severe so it surfaces in the rollup rather than being
      # silently masked by a milder finding.
      statuses.max_by { |status| SEVERITY.index(status) || SEVERITY.length }
    end
  end
end
