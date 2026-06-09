# frozen_string_literal: true

require "bundler"
require "cgi"
require "json"
require "uri"
require_relative "../helpers/http_helper"

module StillActive
  module ArtifactoryClient
    extend self

    # NOT GitHub Packages' /api/v1/gems/.../versions.json
    VERSIONS_API_PATH = "/api/v1/versions/%<gem>s.json"
    SOURCE_URL_PATTERN = %r{\A(https?://[^/]+\.jfrog\.io/[^/]+)/api/gems/([^/]+)/?\z}
    AQL_PATH = "/api/search/aql"

    def artifactory_uri?(uri)
      uri.is_a?(String) && URI(uri).host&.end_with?(".jfrog.io")
    rescue URI::InvalidURIError
      false
    end

    def versions(gem_name:, source_uri:)
      vs = versions_api(gem_name: gem_name, source_uri: source_uri)
      return vs unless vs.empty?

      versions_aql(gem_name: gem_name, source_uri: source_uri)
    rescue Errno::ECONNRESET, Errno::ECONNREFUSED, Net::OpenTimeout, Net::ReadTimeout, SocketError
      []
    end

    private

    def versions_api(gem_name:, source_uri:)
      base = URI(source_uri.chomp("/"))
      path = "#{base.path}#{format(VERSIONS_API_PATH, gem: gem_name)}"
      HttpHelper.get_json(base, path, headers: auth_headers(source_uri)) || []
    end

    def versions_aql(gem_name:, source_uri:)
      artifactory_base, repo_key = parse_source_url(source_uri)
      return [] if artifactory_base.nil?

      base = URI(artifactory_base)
      path = "#{base.path}#{AQL_PATH}"
      body = %(items.find({"name":{"$match":"#{gem_name}-*.gem"},"repo":"#{repo_key}"}).include("name","created"))
      headers = auth_headers(source_uri).merge("Content-Type" => "text/plain")
      response = HttpHelper.post_json(base, path, body: body, headers: headers)
      return [] if response.nil?

      results = response["results"] || []
      build_version_hashes(results: results, gem_name: gem_name)
    end

    def parse_source_url(source_uri)
      match = source_uri.match(SOURCE_URL_PATTERN)
      unless match
        $stderr.puts("warning: unrecognized Artifactory source URL for AQL fallback: #{source_uri}")
        return [nil, nil]
      end

      [match[1], match[2]]
    end

    def build_version_hashes(results:, gem_name:)
      results
        .filter_map do |item|
          version = extract_version(item["name"], gem_name)
          next if version.nil?

          {
            "number" => version,
            "created_at" => item["created"],
            "prerelease" => Gem::Version.new(version).prerelease?,
          }
        end
        .uniq { |h| h["number"] }
        .sort_by { |h| Gem::Version.new(h["number"]) }
        .reverse
    end

    def extract_version(filename, gem_name)
      prefix = "#{gem_name}-"
      return unless filename&.end_with?(".gem") && filename.start_with?(prefix)

      version_part = filename[prefix.length..-5]
      return if version_part.nil? || version_part.empty?

      parse_version_from_filename_tail(version_part)
    end

    # Given the portion of a `.gem` filename after `name-`, returns the
    # leading semver (e.g. `7.0.0` from `7.0.0-x86_64-linux`). Ignores
    # unrelated artifacts that share a prefix (e.g. `datadog-ruby_core_source`
    # when the gem name is `datadog`).
    def parse_version_from_filename_tail(version_part)
      segments = version_part.split("-")
      segments.length.times do |i|
        candidate = segments[0, i + 1].join("-")
        return candidate if Gem::Version.correct?(candidate)
      end
      nil
    end

    def credentials(source_uri)
      host = URI(source_uri).host
      creds = Bundler.settings[source_uri] || Bundler.settings[host]
      creds && !creds.empty? ? creds : StillActive.config.artifactory_token
    end

    def auth_headers(source_uri)
      creds = credentials(source_uri)
      return {} unless creds

      if creds.include?(":")
        user, pass = creds.split(":", 2).map { |part| CGI.unescape(part) }
        { "Authorization" => "Basic #{["#{user}:#{pass}"].pack("m0")}" }
      else
        { "Authorization" => "Bearer #{creds}" }
      end
    end
  end
end
