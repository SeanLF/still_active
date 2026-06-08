# frozen_string_literal: true

require "gems"

module StillActive
  # Turns a gem's catalog siblings into ranked "leads" -- the most-downloaded
  # still-published alternatives. Best-effort: a failed lookup drops that
  # candidate, never the feature.
  module AlternativesHelper
    extend self

    MAX_SIBLINGS_CONSIDERED = 40 # bound the download lookups for huge categories
    DEFAULT_LIMIT = 3

    def leads_for(gem_name:, index:, limit: DEFAULT_LIMIT)
      return [] if index.nil?

      siblings = (index[gem_name] || [])
        .reject { |name| name.include?("/") } # github-slug-only projects can't be ranked by rubygems downloads
        .first(MAX_SIBLINGS_CONSIDERED)
      return [] if siblings.empty?

      siblings
        .filter_map { |name| [name, downloads(name)] if downloads(name) }
        .sort_by { |_name, count| -count }
        .first(limit)
        .map(&:first)
    end

    private

    def downloads(gem_name)
      info = Gems.info(gem_name)
      info && info["downloads"]
    rescue StandardError
      nil
    end
  end
end
