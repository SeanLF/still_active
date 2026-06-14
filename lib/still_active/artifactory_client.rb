# frozen_string_literal: true

require "bundler"
require "cgi"
require "json"
require "uri"
require_relative "../helpers/http_helper"

module StillActive
  module ArtifactoryClient
    extend self

    def artifactory_uri?(uri)
      # Hostnames are case-insensitive, so downcase before the suffix check; an
      # uppercase jfrog host would otherwise be misread as an unqueryable source.
      uri.is_a?(String) && URI(uri).host&.downcase&.end_with?(".jfrog.io")
    rescue URI::InvalidURIError
      false
    end

    def versions(gem_name:, source_uri:)
      headers = auth_headers(gem_name: gem_name, source_uri: source_uri)
      vs = RubygemsClient.versions(gem_name: gem_name, source_uri: source_uri, headers: headers)
      return vs unless vs.empty?

      AqlClient.versions(gem_name: gem_name, source_uri: source_uri, headers: headers)
    rescue Errno::ECONNRESET, Errno::ECONNREFUSED, Net::OpenTimeout, Net::ReadTimeout, SocketError
      []
    end

    private

    def credentials(gem_name:, source_uri:)
      host = URI(source_uri).host
      bundler = Bundler.settings[source_uri] || Bundler.settings[host]
      return bundler if bundler && !bundler.empty?

      global = StillActive.config.artifactory_token
      return unless global

      configured_host = StillActive.config.artifactory_host
      unless configured_host && host&.casecmp?(configured_host)
        warn_unauthorized_host(gem_name: gem_name, host: host)
        return
      end

      global
    end

    def warn_unauthorized_host(gem_name:, host:)
      $stderr.puts(
        "warning: an Artifactory token is set but #{host} (source for #{gem_name}) is not an authorized host, " \
          "so the token will not be sent. " \
          "To allow it, set --artifactory-host=#{host} or STILL_ACTIVE_ARTIFACTORY_HOST=#{host}",
      )
    end

    def auth_headers(gem_name:, source_uri:)
      creds = credentials(gem_name: gem_name, source_uri: source_uri)
      return {} unless creds

      if creds.include?(":")
        user, pass = creds.split(":", 2).map { |part| CGI.unescape(part) }
        { "Authorization" => "Basic #{["#{user}:#{pass}"].pack("m0")}" }
      else
        { "Authorization" => "Bearer #{creds}" }
      end
    end

    # Artifactory's Rubygems-compatible API
    module RubygemsClient
      extend self

      def versions(gem_name:, source_uri:, headers: {})
        base = URI(source_uri.chomp("/"))
        path = "#{base.path}/api/v1/versions/#{encode(gem_name)}.json"
        HttpHelper.get_json(base, path, headers: headers) || []
      end

      private

      def encode(value)
        CGI.escape(value)
      end
    end

    # AQL stands for Artifactory Query Language
    # https://docs.jfrog.com/artifactory/docs/artifactory-query-language
    module AqlClient
      extend self

      SOURCE_URL_PATTERN = %r{\A(https?://[^/]+\.jfrog\.io/[^/]+)/api/gems/([^/]+)/?\z}
      AQL_PATH = "/api/search/aql"

      def versions(gem_name:, source_uri:, headers: {})
        artifactory_base, repo_key = parse_source_url(source_uri)
        return [] if artifactory_base.nil?

        base = URI(artifactory_base)
        path = "#{base.path}#{AQL_PATH}"
        query = {
          "name" => { "$match" => "#{gem_name}-*.gem" },
          "repo" => repo_key,
        }
        body = %(items.find(#{JSON.generate(query)}).include("repo", "path", "name", "created"))
        response = HttpHelper.post_json(base, path, body: body, headers: headers.merge("Content-Type" => "text/plain"))
        return [] if response.nil?

        results = response["results"] || []
        build_version_hashes(results: results, gem_name: gem_name)
      end

      private

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
    end
  end
end
