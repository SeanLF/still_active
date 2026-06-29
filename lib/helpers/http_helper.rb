# frozen_string_literal: true

require "net/http"
require "json"

module StillActive
  module HttpHelper
    TRUSTED_HOSTS = ["github.com", "gitlab.com", "codeberg.org", "api.deps.dev", "endoflife.date", "rubygems.pkg.github.com", "repos.ecosyste.ms"].freeze
    MAX_REDIRECTS = 3
    # Ceiling on a single response body. These are metadata endpoints (version
    # lists, scorecards, advisories); legitimate responses are well under this.
    # A source URL is lockfile-derived and a `*.jfrog.io` host is attacker-
    # registerable, so without a cap a hostile or broken source could stream a
    # multi-GB body and OOM the process. 16 MiB leaves generous headroom for a
    # gem with thousands of versions while bounding worst-case memory.
    MAX_BODY_BYTES = 16 * 1024 * 1024

    extend self

    def get_json(base_uri, path, headers: {}, params: {})
      uri = base_uri.dup
      uri.path = path
      uri.query = URI.encode_www_form(params) unless params.empty?

      request_json(uri, headers) { |target| Net::HTTP::Get.new(target) }
    end

    def post_json(base_uri, path, body:, headers: {})
      uri = base_uri.dup
      uri.path = path

      request_json(uri, headers) do |target|
        request = Net::HTTP::Post.new(target)
        request.body = body
        request
      end
    end

    private

    # Two URIs share an origin when scheme, host, and port all match. URI fills
    # in the default port (443 for https), so the bare and explicit forms of the
    # same origin compare equal.
    def same_origin?(a, b)
      a.scheme == b.scheme && a.host == b.host && a.port == b.port
    end

    # Runs the request, following up to MAX_REDIRECTS trusted-host redirects,
    # and returns the parsed JSON (or nil). The block is yielded each URI and
    # returns the request object, so GET and POST share the redirect/auth/cap
    # logic.
    def request_json(uri, headers)
      MAX_REDIRECTS.times do
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 10
        http.read_timeout = 10

        request = yield(uri)
        headers.each { |key, value| request[key] = value }

        outcome, payload = perform(http, request, uri)
        case outcome
        when :done
          return payload
        when :stop
          return
        when :redirect
          location = payload["Location"]
          if location.nil? || location.empty?
            $stderr.puts("warning: #{uri.host}#{uri.path} returned HTTP #{payload.code} with no Location header")
            return
          end

          redirect_uri = uri + location
          unless TRUSTED_HOSTS.include?(redirect_uri.host)
            $stderr.puts("warning: #{uri.host}#{uri.path} redirected to untrusted host #{redirect_uri.host}, skipping")
            return
          end
          # We dial every request over TLS (use_ssl = true). A redirect that
          # downgrades to http is either a misconfiguration or a downgrade
          # attempt; refuse it rather than silently dialing http-over-TLS.
          unless redirect_uri.scheme == "https"
            $stderr.puts("warning: #{uri.host}#{uri.path} redirected to non-https #{redirect_uri.scheme} target, skipping")
            return
          end
          $stderr.puts("warning: #{uri.host}#{uri.path} redirected to #{redirect_uri.host}#{redirect_uri.path} (stale metadata?)")
          # Auth is scoped to an origin (scheme + host + port), not just a host:
          # a different port is a different service and must not inherit the token.
          headers = {} unless same_origin?(uri, redirect_uri)
          uri = redirect_uri
        end
      end

      $stderr.puts("warning: #{uri.host}#{uri.path} too many redirects")
      nil
    rescue Net::OpenTimeout, Net::ReadTimeout, SocketError, Errno::ECONNREFUSED, Errno::ECONNRESET => e
      $stderr.puts("warning: #{uri.host}#{uri.path} failed: #{e.class} (#{e.message})")
      nil
    rescue JSON::ParserError => e
      $stderr.puts("warning: #{uri.host}#{uri.path} returned invalid JSON: #{e.message}")
      nil
    rescue URI::InvalidURIError => e
      $stderr.puts("warning: #{uri.host}#{uri.path} returned an invalid redirect Location: #{e.message}")
      nil
    end

    # Issues the request in streaming form so the body is read against a size
    # cap rather than buffered whole. Returns one of:
    #   [:redirect, response]  a 3xx, for the caller to follow
    #   [:stop, nil]           non-success (warns unless 404), or body over cap
    #   [:done, parsed]        a 2xx with parsed JSON
    # Redirect and non-success bodies are never read: returning from the block
    # unwinds through Net::HTTP, which closes the connection without draining
    # the body, so a huge error/redirect body can't OOM us either.
    def perform(http, request, uri)
      http.request(request) do |response|
        return [:redirect, response] if response.is_a?(Net::HTTPRedirection)

        unless response.is_a?(Net::HTTPSuccess)
          $stderr.puts("warning: #{uri.host}#{uri.path} returned HTTP #{response.code}") unless response.is_a?(Net::HTTPNotFound)
          return [:stop, nil]
        end

        body = read_capped_body(response, uri)
        return [:stop, nil] if body.nil?

        return [:done, JSON.parse(body)]
      end
    end

    # Reads the body in chunks, abandoning the read (returns nil) as soon as it
    # exceeds MAX_BODY_BYTES so an oversized body is never fully materialized.
    def read_capped_body(response, uri)
      body = +""
      response.read_body do |chunk|
        body << chunk
        if body.bytesize > MAX_BODY_BYTES
          $stderr.puts("warning: #{uri.host}#{uri.path} response exceeded #{MAX_BODY_BYTES} bytes, skipping")
          return nil
        end
      end
      body
    end
  end
end
