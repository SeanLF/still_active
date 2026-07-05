# frozen_string_literal: true

require_relative "../helpers/http_helper"

module StillActive
  module DepsDevClient
    extend self

    BASE_URI = URI("https://api.deps.dev/")

    # A known-vulnerable package used to canary the `advisoryKeys` schema. deps.dev
    # is an explicitly ALPHA API (v3alpha), and every cross-ecosystem vulnerability
    # count flows through the `advisoryKeys` field with a field-level degrade to
    # `[]` -- so a rename or drop of that field would silently turn every count to
    # 0 and read a known-vulnerable package as clean (exit 0). django 3.0.0 carries
    # 30+ permanent advisories; if the canary returns none, the schema drifted.
    ADVISORY_CANARY = { system: "pypi", name: "django", version: "3.0.0" }.freeze

    # Is deps.dev still returning advisories in the shape we parse? False when the
    # canary comes back empty (schema drift) or unreachable (can't confirm). The
    # caller warns loudly rather than presenting a possibly-understated "all clear".
    def advisory_schema_ok?
      info = version_info(gem_name: ADVISORY_CANARY[:name], version: ADVISORY_CANARY[:version], system: ADVISORY_CANARY[:system])
      !(info.nil? || info[:advisory_keys].empty?)
    end

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
        # The locked version's release date -- the cross-ecosystem libyear input
        # (paired with the package's latest-release date). Already in this response,
        # so no extra fetch; nil when the feed omits it.
        published_at: body["publishedAt"],
      }
    end

    # The package's default version and its release date: { version:,
    # published_at: }, or nil. deps.dev's default version is the latest stable;
    # when none is flagged (all pre-release), the newest publishedAt stands in so
    # a still-active package isn't mis-read as dormant. The version is exposed (not
    # just the date) so a caller can recover the package's repo link from it when
    # an exact locked version isn't indexed (yanked/normalization mismatch).
    def default_version_info(name:, system: :rubygems)
      return if name.nil?

      path = "/v3alpha/systems/#{encode(system)}/packages/#{encode(name)}"
      body = HttpHelper.get_json(BASE_URI, path)
      return if body.nil?

      versions = body["versions"]
      return unless versions.is_a?(Array) && !versions.empty?

      entry = versions.find { |v| v.is_a?(Hash) && v["isDefault"] } || newest_version(versions)
      return if entry.nil?

      { version: entry.dig("versionKey", "version"), published_at: entry["publishedAt"] }
    end

    # The package's most recent release date (ISO8601 string), or nil. This is
    # the cross-ecosystem freshness signal, and deps.dev's publishedAt is more
    # reliable than ecosyste.ms's latest_release_published_at, which can lag badly
    # (mpmath: 2023 vs 2026).
    def latest_release_date(name:, system: :rubygems)
      default_version_info(name: name, system: system)&.dig(:published_at)
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
        # deps.dev's v3alpha returns aliases as bare id strings (["CVE-..."]);
        # tolerate the legacy object shape ({"id":...}) too since it's an alpha API.
        aliases: Array(body["aliases"]).filter_map { |a| a.is_a?(Hash) ? a["id"] : a },
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

      # deps.dev returns SOURCE_REPO in many shapes: `https://`, but also `git://`,
      # `git+https://`, `git+ssh://git@...`, `ssh://git@...`. Strip the `git+` prefix,
      # any `scheme://`, and ssh userinfo (`git@`) so what remains is host/owner/repo.
      # Left unnormalized, a git-scheme URL mis-parses (host becomes `git:`), which
      # 400s the projects lookup and drops the repo signals.
      cleaned = url.strip.delete_prefix("git+").sub(%r{\A[a-z][a-z0-9+.-]*://}i, "").sub(%r{\A[^/@]+@}, "")
      # scp-style git remotes separate host from path with a colon (`host:owner/repo`)
      # rather than a slash. Convert it so the split yields host/owner/repo, but leave
      # a real port (`host:443/...`) alone -- a colon before a digit isn't a path.
      cleaned = cleaned.sub(%r{\A([^/:]+):(?=\D)}, '\1/')
      host, *segments = cleaned.split("/")
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
