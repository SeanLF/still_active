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
    SEVERITY = [:unknown, :ok, :legacy, :stale, :archived, :vulnerable, :dead].freeze

    # Returns :dead, :vulnerable, :archived, :legacy, :stale, :ok, or :unknown.
    def gem_status(gem_data)
      vulnerable = gem_data[:vulnerability_count].to_i.positive?

      # A pinned version the registry can't resolve (yanked, typo, or nonexistent)
      # has no version-specific data to judge, so package-level health must not read
      # it as :ok. Absence of data is :unknown, never a false all-clear. Guarded on
      # `!vulnerable` so a detected advisory always wins, in case a future source
      # ever attaches one to an otherwise-unresolved version.
      return :unknown if gem_data[:version_unresolved] && !vulnerable

      level = ActivityHelper.activity_level(gem_data)

      if vulnerable
        # A vulnerability in a dormant or archived gem won't be patched -> :dead;
        # in an actively-released gem a fix is plausible -> :vulnerable.
        return [:critical, :archived].include?(level) ? :dead : :vulnerable
      end

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
