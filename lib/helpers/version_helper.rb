# frozen_string_literal: true

module StillActive
  module VersionHelper
    def find_version(versions:, version_string: nil, pre_release: false)
      if !version_string.nil?
        versions.find { |v| v["number"] == version_string }
      else
        versions.find { |v| v["prerelease"] == pre_release }
      end
    end

    def up_to_date?(version_used:, latest_version: nil, latest_pre_release_version: nil)
      return nil if latest_version.nil? && latest_pre_release_version.nil?

      version_used = if version_used.is_a?(String)
        version_used
      else
        gem_version(version_hash: version_used)
      end

      latest_version = if latest_version.is_a?(String)
        latest_version
      else
        gem_version(version_hash: latest_version)
      end
      latest_pre_release_version = if latest_pre_release_version.is_a?(String)
        latest_pre_release_version
      else
        gem_version(version_hash: latest_pre_release_version)
      end

      [latest_version, latest_pre_release_version].include?(version_used)
    end

    def gem_version(version_hash:)
      version_hash&.dig("number")
    end

    def release_date(version_hash:)
      release_date = version_hash&.dig("created_at")

      Time.parse(release_date) unless release_date.nil?
    end
  end
end
