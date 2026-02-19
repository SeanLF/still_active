# frozen_string_literal: true

require "net/http"
require "json"

module StillActive
  module DepsDevClient
    extend self

    BASE_URI = URI("https://api.deps.dev/")

    def version_info(gem_name:, version:)
      return if gem_name.nil? || version.nil?

      path = "/v3alpha/systems/rubygems/packages/#{encode(gem_name)}/versions/#{encode(version)}"
      body = get(path)
      return if body.nil?

      {
        advisory_keys: body.dig("advisoryKeys")&.map { |a| a["id"] } || [],
        project_id: extract_project_id(body),
      }
    end

    def project_scorecard(project_id:)
      return if project_id.nil?

      path = "/v3alpha/projects/#{encode(project_id)}"
      body = get(path)
      return if body.nil?

      scorecard = body["scorecard"]
      return if scorecard.nil?

      {
        score: scorecard["overallScore"],
        date: scorecard["date"],
      }
    end

    private

    # Extracts "host/owner/repo" from the SOURCE_REPO link URL.
    # URLs may have trailing slashes or extra path segments (e.g. /tree/v1.0).
    def extract_project_id(body)
      url = body.dig("links")&.find { |l| l["label"] == "SOURCE_REPO" }&.dig("url")
      return if url.nil?

      path = url.delete_prefix("https://").delete_prefix("http://")
      segments = path.split("/")
      segments[0..2].join("/") if segments.length >= 3
    end

    def get(path)
      uri = BASE_URI.dup
      uri.path = path
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = 10
      http.read_timeout = 10

      response = http.request(Net::HTTP::Get.new(uri))
      return unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body)
    rescue Net::OpenTimeout, Net::ReadTimeout, SocketError, Errno::ECONNREFUSED
      nil
    end

    def encode(value)
      URI.encode_www_form_component(value)
    end
  end
end
