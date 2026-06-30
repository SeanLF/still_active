# frozen_string_literal: true

require_relative "../helpers/http_helper"

module StillActive
  module DepsDevClient
    extend self

    BASE_URI = URI("https://api.deps.dev/")

    # `system` is the deps.dev package system, lowercased: rubygems, npm, pypi,
    # cargo, go, maven, nuget. It matches the ecosystem symbol SbomReader emits,
    # so a cross-ecosystem caller threads it straight through. An unknown system
    # 404s and degrades to nil (HttpHelper swallows 404), never raising.
    def version_info(gem_name:, version:, system: :rubygems)
      return if gem_name.nil? || version.nil?

      path = "/v3alpha/systems/#{encode(system)}/packages/#{encode(gem_name)}/versions/#{encode(version)}"
      body = HttpHelper.get_json(BASE_URI, path)
      return if body.nil?

      {
        advisory_keys: body.dig("advisoryKeys")&.map { |a| a["id"] } || [],
        project_id: extract_project_id(body),
      }
    end

    # The package's most recent release date (ISO8601 string), or nil. This is
    # the cross-ecosystem freshness signal: deps.dev's default version is the
    # latest stable, and its publishedAt is more reliable than ecosyste.ms's
    # latest_release_published_at, which can lag badly (mpmath: 2023 vs 2026).
    # When no version is flagged default (all pre-release), fall back to the
    # newest publishedAt so a still-active package isn't mis-read as dormant.
    def latest_release_date(name:, system: :rubygems)
      return if name.nil?

      path = "/v3alpha/systems/#{encode(system)}/packages/#{encode(name)}"
      body = HttpHelper.get_json(BASE_URI, path)
      return if body.nil?

      versions = body["versions"]
      return unless versions.is_a?(Array) && !versions.empty?

      default = versions.find { |v| v.is_a?(Hash) && v["isDefault"] }
      (default || newest_version(versions))&.dig("publishedAt")
    end

    def project_scorecard(project_id:)
      return if project_id.nil?

      path = "/v3alpha/projects/#{encode(project_id)}"
      body = HttpHelper.get_json(BASE_URI, path)
      return if body.nil?

      scorecard = body["scorecard"]
      return if scorecard.nil?

      {
        score: scorecard["overallScore"],
        date: scorecard["date"],
        # The "Maintained" sub-check (0-10) scores recent commit and issue
        # activity directly -- still_active's core question -- so we surface it
        # alongside the aggregate. nil when the check is absent (never 0, which
        # would read as "unmaintained" rather than "not measured").
        maintained: maintained_check_score(scorecard),
      }
    end

    def advisory_detail(advisory_id:)
      return if advisory_id.nil?

      path = "/v3alpha/advisories/#{encode(advisory_id)}"
      body = HttpHelper.get_json(BASE_URI, path)
      return if body.nil?

      {
        id: body.dig("advisoryKey", "id"),
        url: body["url"],
        title: body["title"],
        aliases: body["aliases"]&.filter_map { |a| a["id"] } || [],
        cvss3_score: body["cvss3Score"],
        cvss3_vector: body["cvss3Vector"],
        cvss2_score: body["cvss2Score"],
        source: "deps.dev",
      }
    end

    private

    # The OpenSSF "Maintained" check score (0-10), or nil when it's absent. A
    # malformed (non-array) `checks` payload also yields nil rather than raising:
    # this is a best-effort enrichment and must never crash the per-gem audit and
    # vanish the gem from the output via the workflow's rescue.
    def maintained_check_score(scorecard)
      Array(scorecard["checks"]).find { |c| c.is_a?(Hash) && c["name"] == "Maintained" }&.dig("score")
    end

    # Builds a deps.dev project id ("host/owner/repo", or a deeper path for
    # GitLab subgroups) from the SOURCE_REPO link URL. GitHub/Bitbucket projects
    # are always host/owner/repo, but GitLab namespaces nest arbitrarily
    # (host/group/subgroup/.../project), so we can't just keep three segments.
    def extract_project_id(body)
      url = body.dig("links")&.find { |l| l["label"] == "SOURCE_REPO" }&.dig("url")
      return if url.nil?

      host, *segments = url.sub(%r{\Ahttps?://}, "").split("/")
      segments = repo_path_segments(host, segments)
      return if host.nil? || segments.empty?

      [host, *segments].join("/")
    end

    # Trims a repo URL's path to just the project. On GitLab the project path
    # ends at the "/-/" separator (before tree/blob/etc) and may be nested;
    # elsewhere it's owner/repo. Drops trailing slashes and a ".git" suffix.
    def repo_path_segments(host, segments)
      segments = segments.reject(&:empty?)

      if host.to_s.start_with?("gitlab.")
        separator = segments.index("-")
        segments = segments[0...separator] if separator
      else
        segments = segments.first(2)
      end

      segments[-1] = segments[-1].delete_suffix(".git") unless segments.empty?
      segments
    end

    # The version with the newest publishedAt, used only when no version is
    # flagged default. Versions without a publishedAt are dropped; the rest
    # compare lexicographically (deps.dev returns RFC3339 UTC, so string order
    # is chronological), and a dated release always wins over an undated one.
    def newest_version(versions)
      versions
        .select { |v| v.is_a?(Hash) && v["publishedAt"] }
        .max_by { |v| v["publishedAt"].to_s }
    end

    def encode(value)
      URI.encode_www_form_component(value.to_s)
    end
  end
end
