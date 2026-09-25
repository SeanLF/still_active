# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"

module StillActive
  # An on-disk cache of public sources' JSON answers, so a rerun, or the baseline
  # and current audits of one CI job, don't ask for the same thing twice. Only the
  # hosts and paths in RULES are cached, each for as long as that data can be
  # trusted to hold: an answer that carries advisories for an hour, so a new CVE
  # is at most an hour late (--no-cache for none), a published version's record
  # for a week, since it doesn't change. Nothing credentialed is cached: those
  # hosts aren't listed, and a request with an Authorization header is skipped
  # whatever its host. Failures and 404s aren't cached, only answers.
  #
  # OSV's version query is deliberately absent. It is the arbiter that drops a
  # deps.dev finding the version isn't affected by, so it must never be older
  # than the deps.dev record it judges; cached separately, it could be, and would
  # drop an advisory published after it was cached.
  module HttpCache
    extend self

    HOUR = 60 * 60
    DAY = 24 * HOUR
    WEEK = 7 * DAY

    # [host, path pattern, seconds], first match wins.
    RULES = [
      ["api.deps.dev", %r{\A/v3alpha/systems/[^/]+/packages/[^/]+/versions/[^/]+:requirements\z}, WEEK],
      ["api.deps.dev", %r{\A/v3alpha/systems/[^/]+/packages/[^/]+/versions/}, HOUR], # carries advisoryKeys
      ["api.deps.dev", %r{\A/v3alpha/systems/[^/]+/packages/[^/]+\z}, 6 * HOUR], # latest version
      ["api.deps.dev", %r{\A/v3alpha/advisories/}, 6 * HOUR], # CVSS, which the severity gates read
      ["api.deps.dev", %r{\A/v3alpha/projects/}, DAY],
      ["api.osv.dev", %r{\A/v1/vulns/}, 6 * HOUR], # severity and fixed versions
      ["rubygems.org", %r{\A/api/v1/versions/}, 6 * HOUR],
      ["rubygems.org", %r{\A/api/v1/gems/}, DAY],
      ["pypi.org", %r{\A/pypi/[^/]+/[^/]+/json\z}, WEEK], # one published version
      ["packages.ecosyste.ms", %r{/versions/}, WEEK], # one published version's declared deps
      ["repos.ecosyste.ms", %r{\A/api/v1/hosts/}, DAY],
      ["endoflife.date", %r{\A/api/}, DAY]
    ].freeze

    # Entries older than any rule allows are deleted when the cache is first used.
    MAX_AGE = WEEK

    # Seconds to cache this request's answer for, or nil to not cache it.
    def ttl(uri, headers)
      return unless StillActive.config.http_cache
      return if headers.keys.any? { _1.to_s.casecmp?("Authorization") }

      RULES.find { |host, pattern, _| uri.host == host && uri.path.match?(pattern) }&.last
    end

    # The cached answer, or :miss.
    def read(key, ttl)
      path = path_for(key)
      return :miss unless File.exist?(path)

      entry = JSON.parse(File.read(path))
      age = Time.now.to_f - entry.fetch("stored_at")
      # A future stamp (clock skew, a cache restored from another machine) would
      # otherwise never expire.
      return :miss if age.negative? || age > ttl

      entry.fetch("body")
    rescue JSON::ParserError, KeyError, TypeError, SystemCallError
      :miss
    end

    # Best-effort: a cache that can't be written is just a cache miss next time.
    def write(key, body)
      sweep_once
      path = path_for(key)
      FileUtils.mkdir_p(File.dirname(path))
      temp = "#{path}.#{Process.pid}.#{rand(1 << 32)}.tmp"
      File.write(temp, JSON.generate({"stored_at" => Time.now.to_f, "body" => body}))
      File.rename(temp, path)
    rescue SystemCallError, IOError
      File.delete(temp) if temp && File.exist?(temp)
    end

    def key(method, uri)
      Digest::SHA256.hexdigest("#{method}\n#{uri}")
    end

    def directory
      base = ENV["XDG_CACHE_HOME"]
      base = File.join(Dir.home, ".cache") if base.nil? || base.empty?
      File.join(base, "still_active", "http")
    end

    private

    def path_for(key)
      File.join(directory, key[0, 2], "#{key}.json")
    end

    def sweep_once
      return if @swept

      @swept = true
      cutoff = Time.now - MAX_AGE
      Dir.glob(File.join(directory, "*", "*.{json,tmp}")).each { File.delete(_1) if File.mtime(_1) < cutoff }
    rescue SystemCallError
      nil
    end
  end
end
