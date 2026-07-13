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
      licenses = version_hash&.dig("licenses")
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
      #   - SemVer build metadata (cargo's "1.0.4+wasi-0.2.12"), which SemVer 2.0.0
      #     sec 10 says MUST be ignored for precedence anyway
      # rubygems/npm/pypi versions are digit-first with no "+", so this is a no-op.
      str = str.delete_prefix("v").sub(/\+.*\z/, "")
      Gem::Version.new(str) if Gem::Version.correct?(str)
    end
  end
end
