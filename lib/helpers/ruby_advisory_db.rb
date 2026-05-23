# frozen_string_literal: true

module StillActive
  # Optional second vulnerability source: rubysec/ruby-advisory-db, read through
  # bundler-audit's own loader when the user has it installed. We are a consumer —
  # no YAML parsing or version-range matching of our own. Advisories are mapped
  # into the same shape as deps.dev results and merged by VulnerabilityHelper.
  #
  # Verified against bundler-audit 0.9.3: Advisory CVSS scores live in #to_h
  # (:cvss_v3 / :cvss_v2), not in dedicated methods; Database.new raises
  # ArgumentError when the ~/.local/share/ruby-advisory-db checkout is absent.
  module RubyAdvisoryDb
    extend self

    STALE_AFTER_SECONDS = 30 * 24 * 60 * 60 # 30 days

    # bundler-audit's Database#check_gem expects an object responding to
    # #name and #version (a Gem::Version).
    GemRef = Struct.new(:name, :version)

    # Returns a loaded bundler-audit Database, or nil when bundler-audit isn't
    # installed or its advisory checkout is absent. Never raises — a missing
    # second source just means we fall back to deps.dev only.
    def load
      require "bundler/audit"
      require "bundler/audit/database"
      database = Bundler::Audit::Database.new
      warn_if_stale(database)
      database
    rescue LoadError
      nil # bundler-audit not installed
    rescue ArgumentError
      warn("still_active: ruby-advisory-db not found — run `bundle audit update` to enable dual-source vulnerability data")
      nil
    end

    # Maps advisories the database reports for gem_name@version into our
    # vulnerability shape. Returns [] when the database is unavailable or the
    # version can't be parsed (e.g. a git sha). A malformed advisory in the
    # checkout (a corrupt/partial `bundle audit update`) is surfaced, not
    # swallowed — silently returning [] there would hide a missed vulnerability.
    def advisories_for(database:, gem_name:, version:)
      return [] if database.nil?

      parsed = parse_version(version)
      return [] if parsed.nil?

      advisories = []
      database.check_gem(GemRef.new(gem_name, parsed)) { |advisory| advisories << to_vulnerability(advisory) }
      advisories
    rescue Gem::Requirement::BadRequirementError => e
      warn("still_active: ruby-advisory-db has a malformed advisory for #{gem_name} (#{e.message}) — run `bundle audit update` to repair the checkout")
      []
    end

    # Translates a bundler-audit Advisory into the deps.dev-compatible hash.
    # bundler-audit has no CVSS vector, so cvss3_vector is always nil here.
    def to_vulnerability(advisory)
      primary = advisory.ghsa_id || advisory.cve_id || advisory.id
      details = advisory.to_h
      {
        id: primary,
        url: details[:url],
        title: details[:title],
        aliases: advisory.identifiers.reject { |identifier| identifier == primary },
        cvss3_score: details[:cvss_v3],
        cvss3_vector: nil,
        cvss2_score: details[:cvss_v2],
        source: "ruby-advisory-db",
      }
    end

    private

    # nil for versions Gem::Version can't parse (e.g. a git sha); such a "version"
    # has nothing to match in the advisory DB, so the caller returns [].
    def parse_version(version)
      Gem::Version.new(version)
    rescue ArgumentError
      nil
    end

    def warn_if_stale(database)
      updated = database.last_updated_at
      return if updated.nil? # can't determine age — don't warn (not a swallowed error)

      age = Time.now - updated
      return if age < STALE_AFTER_SECONDS

      warn("still_active: ruby-advisory-db is #{(age / 86_400).round} days old — run `bundle audit update` for current advisories")
    end
  end
end
