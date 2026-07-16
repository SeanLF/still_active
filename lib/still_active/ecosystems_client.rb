# frozen_string_literal: true

require "time"
require_relative "../helpers/http_helper"
require_relative "version"

module StillActive
  # Tokenless repo signals (archived?, last-commit date) for github.com-hosted
  # gems, sourced from ecosyste.ms instead of the GitHub API. Used as the
  # fallback when no GitHub token is configured, so an unauthenticated run isn't
  # capped at GitHub's 60 req/hr (ecosyste.ms allows 5000 anonymous) -- the
  # difference between "works on a large Gemfile" and "dies after a handful".
  #
  # GitHub-only by design: ecosyste.ms's repos service doesn't populate commit
  # recency for GitLab/Codeberg (its repo crawler is GitHub-centric), so those
  # hosts keep their own live clients.
  #
  # Data is CC-BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/);
  # still_active queries it live (no redistribution) and attributes ecosyste.ms
  # in the README data sources.
  module EcosystemsClient
    extend self

    BASE_URI = URI("https://repos.ecosyste.ms/")
    # The packages service is a distinct host from the repos service above; it
    # carries per-version declared dependency constraints (the poison-pill input).
    PACKAGES_BASE_URI = URI("https://packages.ecosyste.ms/")
    # ecosyste.ms asks consumers to identify themselves for its "polite pool".
    USER_AGENT = "still_active/#{StillActive::VERSION} (+https://github.com/SeanLF/still_active)".freeze

    # archived + last-commit date from a single repository call. ecosyste.ms's
    # pushed_at mirrors GitHub's, so this returns the same shape as GithubClient.
    # Returns {} when the repo can't be read, so the caller leaves both blank.
    def repo_signals(owner:, name:)
      return {} if owner.nil? || name.nil?

      path = "/api/v1/hosts/GitHub/repositories/#{encode_repo(owner, name)}"
      body = HttpHelper.get_json(BASE_URI, path, headers: { "User-Agent" => USER_AGENT }, params: politeness_params)
      # A non-Hash 200 body (error envelope rendered as an array, schema drift)
      # would otherwise raise on indexing and vanish the gem from the audit via
      # the workflow's rescue; degrade to "no signal" like any other read failure.
      return {} unless body.is_a?(Hash)

      signals = { last_commit_date: parse_time(body["pushed_at"], owner, name) }
      # Only assert archived when the field is actually present. A missing field
      # must read as unknown, not be invented as false -- otherwise a partial
      # crawl could silently mask the most actionable verdict (gem is archived).
      signals[:archived] = body["archived"] == true if body.key?("archived")
      signals
    end

    # ecosyste.ms dependency-kind labels that ship at RUNTIME (so a cap on one
    # holds the consumer's tree hostage). It is registry-specific vocabulary:
    # rubygems/npm/pypi say "runtime", but cargo says "normal" (its "dev"/"build"
    # kinds are excluded). An ALLOWLIST, not a denylist: an unrecognised kind is
    # dropped rather than risk flagging a dev/build dep and breaking the FP
    # discipline. Compared case-insensitively (rubygems's dev kind is
    # "Development").
    RUNTIME_KINDS = ["runtime", "normal"].freeze

    # The runtime dependency constraints a package version declares: an array of
    # { package_name:, requirements: } for runtime-shipped deps only (see
    # RUNTIME_KINDS). Dev/build/test deps are dropped -- they don't cap the
    # consumer's tree, so they can't be a poison-pill. `requirements` is the raw
    # constraint string ("< 5.0, >= 4.0.1") ConstraintHelper reads. `registry` is
    # the ecosyste.ms registry name (rubygems.org, pypi.org, npmjs.org,
    # crates.io), defaulting to Ruby.
    #
    # Returns [] whenever the version can't be read (unindexed, 404, timeout,
    # schema drift), so a caller degrades to "no constraints known" rather than
    # crashing the per-gem audit.
    def declared_dependencies(name:, version:, registry: "rubygems.org")
      return [] if name.nil? || version.nil?

      path = "/api/v1/registries/#{encode(registry)}/packages/#{encode(name)}/versions/#{encode(version)}"
      body = HttpHelper.get_json(PACKAGES_BASE_URI, path, headers: { "User-Agent" => USER_AGENT }, params: politeness_params)
      return [] unless body.is_a?(Hash)

      dependencies = body["dependencies"]
      return [] unless dependencies.is_a?(Array)

      dependencies.filter_map do |dep|
        next unless dep.is_a?(Hash) && RUNTIME_KINDS.include?(dep["kind"].to_s.downcase)

        package_name = dep["package_name"]
        requirements = dep["requirements"]
        next if package_name.nil? || requirements.nil?

        { package_name: package_name, requirements: requirements }
      end
    end

    private

    # ecosyste.ms raises the rate limit and prioritises requests that identify a
    # contact via a mailto query param (its "polite pool"). Opt-in: empty unless
    # the user configures an email, since anonymous already suffices for a typical
    # lockfile and we don't attribute every user's traffic to one address.
    def politeness_params
      email = StillActive.config.ecosystems_email
      email ? { mailto: email } : {}
    end

    # nil or a non-string (numeric/array from an off-spec payload) -> no date,
    # never a crash; only an unparseable string is worth warning about.
    def parse_time(value, owner, name)
      return unless value.is_a?(String)

      Time.parse(value)
    rescue ArgumentError
      $stderr.puts("warning: could not parse repo date for #{owner}/#{name}: #{value.inspect}")
      nil
    end

    def encode_repo(owner, name)
      URI.encode_www_form_component("#{owner}/#{name}")
    end

    def encode(value)
      URI.encode_www_form_component(value.to_s)
    end
  end
end
