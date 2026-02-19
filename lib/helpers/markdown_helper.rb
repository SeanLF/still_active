# frozen_string_literal: true

module StillActive
  module MarkdownHelper
    extend self

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

      formatted_version_used = if data[:version_yanked]
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
      severity = highest_severity(vulnerabilities)
      ids = vulnerabilities.flat_map { |v| [v[:id], *v[:aliases]] }.compact.uniq.first(3)

      parts = [severity ? "#{count} (#{severity})" : count.to_s]
      parts << ids.join(", ") unless ids.empty?
      parts.join(" ")
    end

    def highest_severity(vulnerabilities)
      return if vulnerabilities.empty?

      max_score = vulnerabilities.filter_map { |v| v[:cvss3_score] }.max
      return if max_score.nil?

      case max_score
      when 9.0..Float::INFINITY then "critical"
      when 7.0...9.0 then "high"
      when 4.0...7.0 then "medium"
      else "low"
      end
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
