# frozen_string_literal: true

module StillActive
  module VersionHelper
    extend self

    def find_version(versions:, version_string: nil, pre_release: false)
      if version_string && pre_release
        versions&.find { |v| v["number"] == version_string && v["prerelease"] == pre_release }
      elsif !version_string.nil?
        versions&.find { |v| v["number"] == version_string }
      else
        versions&.find { |v| v["prerelease"] == pre_release }
      end
    end

    def up_to_date(version_used:, latest_version: nil, latest_pre_release_version: nil)
      return if latest_version.nil? && latest_pre_release_version.nil?

      [normalize_version(latest_version), normalize_version(latest_pre_release_version)]
        .include?(normalize_version(version_used))
    end

    def gem_version(version_hash:)
      version_hash&.dig("number")
    end

    def release_date(version_hash:)
      release_date = version_hash&.dig("created_at")

      Time.parse(release_date) unless release_date.nil?
    end

    private

    def normalize_version(version)
      version.is_a?(String) ? version : gem_version(version_hash: version)
    end
  end
end
