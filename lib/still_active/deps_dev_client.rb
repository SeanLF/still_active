# frozen_string_literal: true

require_relative "../helpers/http_helper"

module StillActive
  module DepsDevClient
    extend self

    BASE_URI = URI("https://api.deps.dev/")

    def version_info(gem_name:, version:)
      return if gem_name.nil? || version.nil?

      path = "/v3alpha/systems/rubygems/packages/#{encode(gem_name)}/versions/#{encode(version)}"
      body = HttpHelper.get_json(BASE_URI, path)
      return if body.nil?

      {
        advisory_keys: body.dig("advisoryKeys")&.map { |a| a["id"] } || [],
        project_id: extract_project_id(body),
      }
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
        aliases: body["aliases"]&.map { |a| a["id"] } || [],
        cvss3_score: body["cvss3Score"],
        cvss3_vector: body["cvss3Vector"],
        cvss2_score: body["cvss2Score"],
        source: "deps.dev",
      }
    end

    private

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

    def encode(value)
      URI.encode_www_form_component(value)
    end
  end
end
