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

      # Bound the per-gem download lookups so a huge category can't trigger
      # dozens of HTTP calls. This is a catalog-order prefix, so a very large
      # category could leave a popular sibling past the cap out of the ranking;
      # acceptable for best-effort leads where we only ever surface a few.
      # (CatalogIndex already reduces owner/repo slugs to their gem-name tail,
      # so every entry here is a plain name rankable by downloads.)
      siblings = (index[gem_name] || []).first(MAX_SIBLINGS_CONSIDERED)
      return [] if siblings.empty?

      siblings
        .filter_map { |name| (count = downloads(name)) && [name, count] }
        .max_by(limit) { |_name, count| count }
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
