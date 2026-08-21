# frozen_string_literal: true

require "time"

module StillActive
  module VersionHelper
    extend self

    def find_version(versions:, version_string: nil, pre_release: false)
      if version_string && pre_release
        versions&.find { |v| v["number"] == version_string && v["prerelease"] == pre_release }
      elsif !version_string.nil?
        versions&.find { |v| v["number"] == version_string }
      else
        # The "latest" of a kind: pick the highest by version rather than trust
        # the source's ordering. RubyGems happens to return newest-first, but
        # GitHub Packages and other sources don't, and a wrong "latest" cascades
        # into up_to_date and libyear.
        versions
          &.select { |v| v["prerelease"] == pre_release }
          &.max_by { |v| to_gem_version(v["number"]) || Gem::Version.new("0") }
      end
    end

    # The latest pre-release is only a useful signal when it is newer than the
    # latest stable release: an upcoming version you could opt into. A pre-release
    # that predates the latest stable is historical noise (e.g. a lone 2009 `rc`
    # on a gem now at 0.9.x, or an `8.1.0.rc1` after `8.1.2` already shipped), and
    # it silently corrupts downstream logic: up_to_date compares `used >=`
    # latest_pre_release, so any current version reads `>=` a stale pre-release and
    # a behind gem is painted up to date (the futurist emoji). Returns the
    # pre-release only when strictly newer than the release; keeps it when there is
    # no stable release at all (a pre-release-only gem), where it is the only signal.
    def upcoming_pre_release(pre_release:, release:)
      return pre_release if release.nil?
      return if pre_release.nil?

      pre = to_gem_version(pre_release)
      stable = to_gem_version(release)
      pre_release if pre && stable && pre > stable
    end

    def up_to_date(version_used:, latest_version: nil, latest_pre_release_version: nil)
      return if latest_version.nil? && latest_pre_release_version.nil?

      used = to_gem_version(version_used)
      return if used.nil?

      [latest_version, latest_pre_release_version]
        .compact
        .filter_map { |v| to_gem_version(v) }
        .any? { |v| used >= v }
    end

    # A Gem::Version for cross-ecosystem comparison (leading "v" and SemVer build
    # metadata normalized away), or nil when the string can't be parsed. Public so
    # the deps.dev client can rank a package's versions to find the real latest
    # stable rather than trusting deps.dev's unreliable `isDefault` flag.
    def comparable(version_string)
      to_gem_version(version_string)
    end

    # Renders a MAJOR.MINOR.PATCH[.prerelease] RubyGems version as SemVer 2.0.0,
    # for fields that require it (SARIF's tool.driver.semanticVersion). A gem
    # prerelease joins its prerelease identifiers to the release with a ".", SemVer
    # with a "-": "3.0.0.rc4" -> "3.0.0-rc4", "1.2.3.pre.5" -> "1.2.3-pre.5". A
    # plain release ("3.0.0") is already SemVer and passes through, and a short
    # numeric release is padded to MAJOR.MINOR.PATCH. A string that doesn't start
    # with a numeric segment is returned unchanged rather than coerced into a bogus
    # version. Scoped to the tool's own version scheme: a 4+-segment numeric
    # release (e.g. a gem like "6.1.7.6") is NOT converted to valid SemVer.
    def to_semver(version_string)
      return version_string if version_string.nil? || version_string.empty?

      parts = version_string.split(".")
      release = parts.take_while { |part| part.match?(/\A\d+\z/) }
      return version_string if release.empty?

      prerelease = parts.drop(release.length)
      release << "0" while release.length < 3
      base = release.join(".")
      prerelease.empty? ? base : "#{base}-#{prerelease.join(".")}"
    end

    def gem_version(version_hash:)
      version_hash&.dig("number")
    end

    def release_date(version_hash:)
      release_date = version_hash&.dig("created_at")

      Time.parse(release_date) unless release_date.nil?
    end

    # The version's declared Ruby requirement (the `ruby_version` field in the
    # RubyGems versions payload, e.g. ">= 3.2", "< 3.2"), or nil when absent. This
    # is the language-runtime ceiling's raw input; note it is `ruby_version`, not
    # the gemspec's `required_ruby_version`.
    def ruby_requirement(version_hash:)
      requirement = version_hash&.dig("ruby_version")
      requirement unless requirement.nil? || requirement.empty?
    end

    # SPDX license identifier(s) from the RubyGems versions payload.
    # Comma-joined when a gem declares more than one. nil when unknown.
    def license(version_hash:)
      format_licenses(version_hash&.dig("licenses"))
    end

    # The shared rendering both paths join through, so a licence reads the same
    # whether it came from RubyGems (native) or deps.dev (--sbom). Both serve an
    # array of SPDX strings, and a single element may itself be an expression
    # ("Apache-2.0 OR MIT"), which passes through untouched. nil when unknown,
    # never an empty string, so a missing licence can't render as a present blank.
    def format_licenses(licenses)
      return if licenses.nil? || licenses.empty?

      licenses.join(", ")
    end

    private

    def normalize_version(version)
      version.is_a?(String) ? version : gem_version(version_hash: version)
    end

    def to_gem_version(version)
      str = normalize_version(version)
      return unless str

      # Normalize two cross-ecosystem shapes Gem::Version can't parse, so a
      # current dependency compares as up to date instead of reading "behind":
      #   - a leading "v" (Go module versions, "v2.0.1")
      #   - SemVer build metadata (cargo's "1.0.4+wasi-0.2.12"), everything from the
      #     first "+", which SemVer 2.0.0 sec 10 says MUST be ignored for precedence
      # rubygems/npm/pypi versions are digit-first with no "+", so this is a no-op.
      # Sliced by index rather than a regex (/\+.*/ on the external version string
      # trips a polynomial-ReDoS scanner, and this is provably linear anyway).
      str = str.delete_prefix("v")
      plus = str.index("+")
      str = str[0, plus] if plus
      Gem::Version.new(str) if Gem::Version.correct?(str)
    end
  end
end
