# frozen_string_literal: true

require "bundler"
require "cgi"
require "json"
require "uri"
require_relative "../helpers/http_helper"
require_relative "compact_index_client"
require_relative "source_credentials"

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

    # Version sources in precedence order:
    #   1. the compact index, the only endpoint that lists what the repo can
    #      actually resolve (#142)
    #   2. the versions API, for hosts that serve no compact index
    #   3. AQL, a cache inventory, when neither answers
    # The compact index carries no timestamps, so a compact-index list is dated
    # from the versions API.
    def versions(gem_name:, source_uri:)
      headers = auth_headers(gem_name: gem_name, source_uri: source_uri)
      compact = CompactIndexClient.versions(gem_name: gem_name, source_uri: source_uri, headers: headers)
      return dated(compact, gem_name: gem_name, source_uri: source_uri, headers: headers) unless compact.empty?

      vs = RubygemsClient.versions(gem_name: gem_name, source_uri: source_uri, headers: headers)
      return vs unless vs.empty?

      AqlClient.versions(gem_name: gem_name, source_uri: source_uri, headers: headers)
    rescue Errno::ECONNRESET, Errno::ECONNREFUSED, Net::OpenTimeout, Net::ReadTimeout, SocketError
      []
    end

    private

    # Matched on the exact version number, so the versions API can only annotate a
    # version the compact index already listed. That keeps a name collision from
    # contributing anything: the placeholder gem's versions simply don't match, and
    # the real ones stay undated rather than borrowing a stranger's release date.
    def dated(versions, gem_name:, source_uri:, headers:)
      return versions if versions.all? { |version| version["created_at"] }

      published = RubygemsClient.versions(gem_name: gem_name, source_uri: source_uri, headers: headers)
      return versions unless published.is_a?(Array)

      by_number = published.grep(Hash).to_h { |version| [version["number"], version] }
      # compact first: an absent compact-index field must not blank out the value
      # the versions API supplied for the same version.
      versions.map { |version| (by_number[version["number"]] || {}).merge(version.compact) }
    end

    # Bundler's own per-host credential (bundle config / BUNDLE_<HOST>) wins, exactly
    # as `bundle install` would use it. Only when the host has none do we consider
    # still_active's ambient --artifactory-token, and only for the one host the user
    # explicitly allowlisted: the token is not host-keyed, so sending it to a
    # lockfile-derived host would leak it. See SourceCredentials for the host-keyed
    # store this shares with the generic private-source path.
    def credentials(gem_name:, source_uri:)
      bundler = Bundler.settings.credentials_for(URI(source_uri))
      return bundler if bundler && !bundler.empty?

      global = StillActive.config.artifactory_token
      return unless global

      host = URI(source_uri).host
      configured_host = StillActive.config.artifactory_host
      unless configured_host && host&.casecmp?(configured_host)
        warn_unauthorized_host(gem_name: gem_name, host: host)
        return
      end

      global
    end

    def warn_unauthorized_host(gem_name:, host:)
      warn(
        "warning: an Artifactory token is set but #{host} (source for #{gem_name}) is not an authorized host, " \
          "so the token will not be sent. " \
          "To allow it, set --artifactory-host=#{host} or STILL_ACTIVE_ARTIFACTORY_HOST=#{host}"
      )
    end

    def auth_headers(gem_name:, source_uri:)
      SourceCredentials.auth_header(credentials(gem_name: gem_name, source_uri: source_uri))
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
          "name" => {"$match" => "#{gem_name}-*.gem"},
          "repo" => repo_key
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
          warn("warning: unrecognized Artifactory source URL for AQL fallback: #{source_uri}")
          return [nil, nil]
        end

        [match[1], match[2]]
      end

      def build_version_hashes(results:, gem_name:)
        results
          .filter_map do |item|
            version = extract_version(item["name"], gem_name)
            next if version.nil?

            # No "created_at": the AQL `created` field is when this Artifactory
            # cached the artifact, not when the version was published. The two
            # agree to within a day for a gem someone pulled promptly and diverge
            # by years for one pulled late, so it cannot back a staleness signal.
            {
              "number" => version,
              "prerelease" => Gem::Version.new(version).prerelease?
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
