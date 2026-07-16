# frozen_string_literal: true

module StillActive
  module Repository
    # codeberg.org is the one Forgejo/Gitea host wired up today; it speaks the
    # same Gitea API as any self-hosted instance, so its source is :forgejo (the
    # forge software, what ForgejoClient handles), not :codeberg (the host).
    SOURCE_BY_HOST = {
      "github.com" => :github,
      "gitlab.com" => :gitlab,
      "codeberg.org" => :forgejo
    }.freeze
    REPO_REGEX = %r{(?<url>https?://(?:www\.)?(?<host>github\.com|gitlab\.com|codeberg\.org)/(?<owner>[\w.-]+)/(?<name>[\w.-]+))}i

    extend self

    def valid?(url:)
      return false if url.nil?

      url.match?(REPO_REGEX)
    end

    def url_with_owner_and_name(url:)
      match = url&.match(REPO_REGEX)
      return {source: :unhandled, owner: nil, name: nil} unless match

      clean_url = match[:url].delete_suffix(".git")
      name = match[:name].delete_suffix(".git")

      {url: clean_url, source: SOURCE_BY_HOST.fetch(match[:host].downcase), owner: match[:owner], name: name}
    end
  end
end
