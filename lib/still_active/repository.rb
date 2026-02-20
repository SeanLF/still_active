# frozen_string_literal: true

module StillActive
  module Repository
    REPO_REGEX = %r{(https?://(?:www\.)?(github|gitlab)\.com/([\w.\-]+)/([\w.\-]+))}i

    extend self

    def valid?(url:)
      return false if url.nil?

      url.match?(REPO_REGEX)
    end

    def url_with_owner_and_name(url:)
      match = url&.match(REPO_REGEX)
      return { source: :unhandled, owner: nil, name: nil } unless match

      url = match[1].delete_suffix(".git")
      name = match[4].delete_suffix(".git")

      { url: url, source: match[2].to_sym, owner: match[3], name: name }
    end
  end
end
