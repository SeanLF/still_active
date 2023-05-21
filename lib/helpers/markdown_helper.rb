# frozen_string_literal: true

module StillActive
  module MarkdownHelper
    extend self
    def markdown_table_header_line
      "| gem activity old? | up to date? | name | version used | release date | latest version | release date | latest pre-release version  | release date | last commit date |\n" \
        "| ----------------- | ----------- | ---- | ------------ | ------------ | -------------- | ------------ | --------------------------- | ------------ | ---------------- |"
    end

    def markdown_table_body_line(gem_name:, data:)
      repository_url = data[:repository_url]
      ruby_gems_url = data[:ruby_gems_url]

      version_used = data.dig(:version_used)
      version_used_url =
        if version_used && ruby_gems_url
          "#{ruby_gems_url}/versions/#{version_used}"
        end
      version_used_release_date = data.dig(:version_used_release_date)

      latest_version = data[:latest_version]
      latest_version_url =
        if latest_version && ruby_gems_url
          "#{ruby_gems_url}/versions/#{latest_version}"
        end
      latest_version_release_date = data.dig(:latest_version_release_date)

      latest_version_prerelease = data.dig(:latest_pre_release_version)
      latest_version_prerelease_url =
        if latest_version_prerelease && ruby_gems_url
          "#{ruby_gems_url}/versions/#{latest_version_prerelease}"
        end
      latest_version_prerelease_date = data.dig(:latest_pre_release_version_release_date)

      last_commit_date = data.dig(:last_commit_date)
      last_commit_url = repository_url

      inactive_repository_emoji = data.dig(:last_activity_warning_emoj)
      using_latest_version_emoji = data.dig(:up_to_date_emoji)

      formatted_name = markdown_url(text: gem_name, url: repository_url)

      formatted_version_used = markdown_url(text: version_used, url: version_used_url)
      formatted_version_used_date = year_month(version_used_release_date)

      formatted_latest_release_version = markdown_url(text: latest_version, url: latest_version_url)
      formatted_latest_release_date = year_month(latest_version_release_date)

      formatted_latest_pre_release_version = markdown_url(
        text: latest_version_prerelease,
        url: latest_version_prerelease_url,
      )
      formatted_latest_pre_release_date = year_month(latest_version_prerelease_date)

      formatted_last_commit_date = markdown_url(text: year_month(last_commit_date), url: last_commit_url)

      formatted_markdown_table_line =
        [
          inactive_repository_emoji || StillActive.config.unsure_emoji,
          using_latest_version_emoji || StillActive.config.unsure_emoji,
          formatted_name,
          formatted_version_used,
          formatted_version_used_date || StillActive.config.unsure_emoji,
          formatted_latest_release_version || StillActive.config.unsure_emoji,
          formatted_latest_release_date || StillActive.config.unsure_emoji,
          formatted_latest_pre_release_version || StillActive.config.unsure_emoji,
          formatted_latest_pre_release_date || StillActive.config.unsure_emoji,
          formatted_last_commit_date || StillActive.config.unsure_emoji,
        ]
          .join(" | ")

      "| #{formatted_markdown_table_line} |"
    end

    private

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
