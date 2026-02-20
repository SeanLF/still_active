# frozen_string_literal: true

require_relative "vulnerability_helper"

module StillActive
  module MarkdownHelper
    extend self

    def ruby_line(ruby_info)
      version = ruby_info[:version]
      latest = ruby_info[:latest_version]
      libyear = ruby_info[:libyear]
      eol = ruby_info[:eol]
      eol_date = ruby_info[:eol_date]

      return "**Ruby #{version}** (latest) #{StillActive.config.success_emoji}" if version == latest

      libyear_part = libyear ? "#{libyear} libyears behind #{latest}" : "behind #{latest}"

      if eol
        eol_part = eol_date ? "EOL #{eol_date.strftime("%Y-%m-%d")}" : "EOL"
        "**Ruby #{version}** (#{eol_part}, #{libyear_part}) #{StillActive.config.critical_warning_emoji}"
      else
        "**Ruby #{version}** (#{libyear_part}) #{StillActive.config.warning_emoji}"
      end
    end

    def markdown_table_header_line
      "| activity | up to date? | OpenSSF | vulns | name | version used | latest version | latest pre-release | last commit | libyear |\n" \
        "| -------- | ----------- | ------- | ----- | ---- | ------------ | -------------- | ------------------ | ----------- | ------- |"
    end

    def markdown_table_body_line(gem_name:, data:)
      repository_url = data[:repository_url]
      ruby_gems_url = data[:ruby_gems_url]

      inactive_repository_emoji = data[:last_activity_warning_emoji]
      using_latest_version_emoji = data[:up_to_date_emoji]

      formatted_name = markdown_url(text: gem_name, url: repository_url)

      formatted_version_used = if [:git, :path].include?(data[:source_type])
        data[:version_used] ? "#{data[:version_used]} (#{data[:source_type]})" : "(#{data[:source_type]})"
      elsif data[:version_yanked]
        "#{data[:version_used]} (YANKED #{StillActive.config.critical_warning_emoji})"
      else
        version_with_date(
          text: data[:version_used],
          url: version_url(ruby_gems_url, data[:version_used]),
          date: data[:version_used_release_date],
        )
      end

      formatted_latest_version = version_with_date(
        text: data[:latest_version],
        url: version_url(ruby_gems_url, data[:latest_version]),
        date: data[:latest_version_release_date],
      )

      formatted_latest_pre_release = version_with_date(
        text: data[:latest_pre_release_version],
        url: version_url(ruby_gems_url, data[:latest_pre_release_version]),
        date: data[:latest_pre_release_version_release_date],
      )

      formatted_last_commit = markdown_url(text: year_month(data[:last_commit_date]), url: repository_url)

      unsure = StillActive.config.unsure_emoji

      cells = [
        inactive_repository_emoji || unsure,
        using_latest_version_emoji || unsure,
        format_scorecard(data[:scorecard_score]),
        format_vulns(data),
        formatted_name,
        formatted_version_used || unsure,
        formatted_latest_version || unsure,
        formatted_latest_pre_release || unsure,
        formatted_last_commit || unsure,
        format_libyear(data[:libyear]),
      ]

      "| #{cells.join(" | ")} |"
    end

    private

    def version_with_date(text:, url:, date:)
      version_part = markdown_url(text: text, url: url)
      return if version_part.nil?

      date_part = year_month(date)
      return version_part unless date_part

      "#{version_part} (#{date_part})"
    end

    def version_url(ruby_gems_url, version)
      return if ruby_gems_url.nil? || version.nil?

      "#{ruby_gems_url}/versions/#{version}"
    end

    def format_scorecard(score)
      return StillActive.config.unsure_emoji if score.nil?

      "#{score}/10"
    end

    def format_libyear(value)
      return "-" if value.nil?

      "#{value}y"
    end

    def format_vulns(data)
      count = data[:vulnerability_count]
      return StillActive.config.unsure_emoji if count.nil?
      return StillActive.config.success_emoji if count.zero?

      vulnerabilities = data[:vulnerabilities] || []
      severity = VulnerabilityHelper.highest_severity(vulnerabilities)
      ids = vulnerabilities.flat_map { |v| [v[:id], *v[:aliases]] }.compact.uniq.first(3)

      parts = [severity ? "#{count} (#{severity})" : count.to_s]
      parts << ids.join(", ") unless ids.empty?
      parts.join(" ")
    end

    def markdown_url(text:, url:)
      return text if url.nil?

      "[#{text}](#{url})"
    end

    def year_month(time_object)
      return if time_object.nil?

      time_object.strftime("%Y/%m")
    end
  end
end
