# frozen_string_literal: true

require "net/http"
require "openssl"
require "json"
require_relative "http_cache"

module StillActive
  module HttpHelper
    TRUSTED_HOSTS = ["github.com", "gitlab.com", "codeberg.org", "api.deps.dev", "api.osv.dev", "endoflife.date", "rubygems.org", "rubygems.pkg.github.com", "repos.ecosyste.ms", "packages.ecosyste.ms", "pypi.org"].freeze
    # Transport-level failures ("host unreachable / connection broke", not an HTTP
    # error status). Every network entry point degrades to a safe empty result on
    # these rather than letting one escape and vanish a gem from the audit.
    # SystemCallError is the superclass of the whole Errno::* family (EHOSTUNREACH,
    # ENETUNREACH, ETIMEDOUT, EPIPE, ECONNREFUSED, ECONNRESET, ...), so we don't
    # have to enumerate each one and miss the next.
    TRANSPORT_ERRORS = [
      Net::OpenTimeout,
      Net::ReadTimeout,
      SocketError,
      SystemCallError,
      OpenSSL::SSL::SSLError,
      EOFError
    ].freeze
    MAX_REDIRECTS = 3
    # A 429 or 503 that says when to come back gets one retry, if that's soon.
    MAX_RETRY_AFTER_SECONDS = 10
    # Idle connections kept per host. The fan-out runs 10 at a time, so more than
    # that would only ever sit idle.
    MAX_IDLE_PER_HOST = 10
    # Ceiling on a single response body. These are metadata endpoints (version
    # lists, scorecards, advisories); legitimate responses are well under this.
    # A source URL is lockfile-derived and a `*.jfrog.io` host is attacker-
    # registerable, so without a cap a hostile or broken source could stream a
    # multi-GB body and OOM the process. 16 MiB leaves generous headroom for a
    # gem with thousands of versions while bounding worst-case memory.
    MAX_BODY_BYTES = 16 * 1024 * 1024
    JSON_PARSER = ->(body) { JSON.parse(body) }
    # Raised in strict mode when the source couldn't answer: a transport error, a
    # non-404 error status, a refused redirect, an oversized or garbled body. A 404
    # is an answer ("no such record") and still returns nil. A caller that must not
    # read a failure as "nothing there", like an advisory lookup, asks for strict.
    Unavailable = Class.new(StandardError)
    IDENTITY = ->(body) { body }

    extend self

    # Close and forget every pooled connection. Specs call it between examples,
    # since a pooled connection holds WebMock's fake socket.
    def reset_connections!
      pool.each_value { |idle| idle.each { close(_1) } }
      @pool = nil
    end

    def get_json(base_uri, path, headers: {}, params: {}, strict: false)
      uri = base_uri.dup
      uri.path = path
      uri.query = URI.encode_www_form(params) unless params.empty?

      cached(HttpCache.key("GET", uri), uri, headers) do
        request_json(uri, headers, strict: strict) { |target| Net::HTTP::Get.new(target) }
      end
    end

    # As get_json, but for endpoints that answer in plain text (the RubyGems
    # compact index). Shares the redirect, auth-scoping and body-cap handling;
    # only the parse step differs.
    def get_text(base_uri, path, headers: {})
      uri = base_uri.dup
      uri.path = path

      request_json(uri, headers, parse: IDENTITY) { |target| Net::HTTP::Get.new(target) }
    end

    def post_json(base_uri, path, body:, headers: {}, strict: false)
      uri = base_uri.dup
      uri.path = path

      cached(HttpCache.key("POST", uri, body), uri, headers) do
        request_json(uri, headers, strict: strict) do |target|
          request = Net::HTTP::Post.new(target)
          request.body = body
          request
        end
      end
    end

    private

    # A cached answer when there's a fresh one; otherwise asks, and caches a
    # non-nil answer. nil is a 404 or a failure, neither of which is kept.
    def cached(key, uri, headers)
      ttl = HttpCache.ttl(uri, headers)
      return yield if ttl.nil?

      hit = HttpCache.read(key, ttl)
      return hit unless hit == :miss

      yield.tap { HttpCache.write(key, _1) unless _1.nil? }
    end

    # Two URIs share an origin when scheme, host, and port all match. URI fills
    # in the default port (443 for https), so the bare and explicit forms of the
    # same origin compare equal.
    def same_origin?(a, b)
      a.scheme == b.scheme && a.host == b.host && a.port == b.port
    end

    # Runs the request, following up to MAX_REDIRECTS trusted-host redirects,
    # and returns the parsed body (or nil), where `parse` decides JSON vs text.
    # The block is yielded each URI and returns the request object, so GET and
    # POST share the redirect/auth/cap logic.
    def request_json(uri, headers, parse: JSON_PARSER, strict: false)
      retried = false
      # The Retry-After retry repeats a pass rather than spending one of these.
      passes = 0
      while (passes += 1) <= MAX_REDIRECTS
        request = yield(uri)
        headers.each { |key, value| request[key] = value }

        outcome, payload = with_connection(uri) { |http| perform(http, request, uri, parse) }
        case outcome
        when :retry_after
          if retried
            warn("warning: #{uri.host}#{uri.path} is still rate limited after one retry")
            return unavailable(strict, uri)
          end
          warn("warning: #{uri.host}#{uri.path} returned HTTP #{payload[:code]}, retrying in #{payload[:seconds]}s as it asked")
          sleep(payload[:seconds])
          retried = true
          passes -= 1
          next
        when :done
          # A 404 is how a source says "no record"; a 200 of `null` says nothing.
          return payload unless payload.nil? && strict

          warn("warning: #{uri.host}#{uri.path} returned an empty (null) body")
          return unavailable(strict, uri)
        when :not_found
          return
        when :stop
          return unavailable(strict, uri)
        when :redirect
          location = payload["Location"]
          if location.nil? || location.empty?
            warn("warning: #{uri.host}#{uri.path} returned HTTP #{payload.code} with no Location header")
            return unavailable(strict, uri)
          end

          redirect_uri = uri + location
          unless TRUSTED_HOSTS.include?(redirect_uri.host)
            warn("warning: #{uri.host}#{uri.path} redirected to untrusted host #{redirect_uri.host}, skipping")
            return unavailable(strict, uri)
          end
          # We dial every request over TLS (use_ssl = true). A redirect that
          # downgrades to http is either a misconfiguration or a downgrade
          # attempt; refuse it rather than silently dialing http-over-TLS.
          unless redirect_uri.scheme == "https"
            warn("warning: #{uri.host}#{uri.path} redirected to non-https #{redirect_uri.scheme} target, skipping")
            return unavailable(strict, uri)
          end
          warn("warning: #{uri.host}#{uri.path} redirected to #{redirect_uri.host}#{redirect_uri.path} (stale metadata?)")
          # Auth is scoped to an origin (scheme + host + port), not just a host:
          # a different port is a different service and must not inherit the token.
          headers = {} unless same_origin?(uri, redirect_uri)
          uri = redirect_uri
        end
      end

      warn("warning: #{uri.host}#{uri.path} too many redirects")
      unavailable(strict, uri)
    rescue *TRANSPORT_ERRORS => e
      warn("warning: #{uri.host}#{uri.path} failed: #{e.class} (#{e.message})")
      unavailable(strict, uri)
    rescue JSON::ParserError => e
      warn("warning: #{uri.host}#{uri.path} returned invalid JSON: #{e.message}")
      unavailable(strict, uri)
    rescue URI::InvalidURIError => e
      warn("warning: #{uri.host}#{uri.path} returned an invalid redirect Location: #{e.message}")
      unavailable(strict, uri)
    end

    # Every failure has already warned; strict callers also get told.
    def unavailable(strict, uri)
      raise Unavailable, "#{uri.host}#{uri.path}" if strict
    end

    # Issues the request in streaming form so the body is read against a size
    # cap rather than buffered whole. Returns one of:
    #   [:redirect, response]  a 3xx, for the caller to follow
    #   [:not_found, nil]      a 404, which is an answer, not a failure
    #   [:stop, nil]           any other non-success (warns), or body over cap
    #   [:done, parsed]        a 2xx with the parsed body (JSON or text)
    # Redirect and error bodies are never read: returning from the block unwinds
    # through Net::HTTP without draining the body, so a huge one can't OOM us, and
    # with_connection closes that connection. A success or a 404 is read to the end
    # and the block finishes normally, so Net::HTTP does its end-of-request
    # bookkeeping: it honours Connection: close and records the time for its idle
    # check, which is what makes the connection safe to pool. Returning from inside
    # skipped both, and a POST on a connection the server had closed then failed.
    def perform(http, request, uri, parse)
      body = nil
      http.request(request) do |response|
        return [:redirect, response] if response.is_a?(Net::HTTPRedirection)

        if response.is_a?(Net::HTTPNotFound)
          return [:stop, nil] if read_capped_body(response, uri).nil?

          next
        end

        if (seconds = retry_after(response))
          return [:retry_after, {code: response.code, seconds: seconds}]
        end

        unless response.is_a?(Net::HTTPSuccess)
          warn("warning: #{uri.host}#{uri.path} returned HTTP #{response.code}")
          return [:stop, nil]
        end

        body = read_capped_body(response, uri)
        return [:stop, nil] if body.nil?
      end
      body.nil? ? [:not_found, nil] : [:done, parse.call(body)]
    end

    # The seconds a 429 or 503 asks us to wait, when it gives a number of them and
    # the wait is short enough to be worth it; nil otherwise. The HTTP-date form is
    # read as "not soon", since the sources we call send seconds.
    def retry_after(response)
      return unless response.code == "429" || response.code == "503"

      value = response["Retry-After"].to_s.strip
      return unless value.match?(/\A\d+\z/)

      value.to_i if value.to_i <= MAX_RETRY_AFTER_SECONDS
    end

    # One started connection per host, reused across requests. Only a success or a
    # 404, read to the end with Net::HTTP's request finished normally, goes back
    # (see perform); anything else may have unread bytes and is closed. On reuse,
    # Net::HTTP reconnects a connection the server closed or that sat idle past
    # its keep-alive timeout.
    def with_connection(uri)
      http = pool[[uri.host, uri.port]].pop || open_connection(uri)
      outcome = nil
      begin
        outcome = yield(http)
      ensure
        if [:done, :not_found].include?(outcome&.first) && pool[[uri.host, uri.port]].size < MAX_IDLE_PER_HOST
          pool[[uri.host, uri.port]] << http
        else
          close(http)
        end
      end
    end

    def open_connection(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = 10
      http.read_timeout = 10
      http.start
    end

    def close(http)
      http.finish if http.started?
    rescue IOError
      nil
    end

    def pool
      @pool ||= Hash.new { |hash, key| hash[key] = [] }
    end

    # Reads the body in chunks, abandoning the read (returns nil) as soon as it
    # exceeds MAX_BODY_BYTES so an oversized body is never fully materialized.
    def read_capped_body(response, uri)
      body = +""
      response.read_body do |chunk|
        body << chunk
        if body.bytesize > MAX_BODY_BYTES
          warn("warning: #{uri.host}#{uri.path} response exceeded #{MAX_BODY_BYTES} bytes, skipping")
          return nil
        end
      end
      body
    end
  end
end
