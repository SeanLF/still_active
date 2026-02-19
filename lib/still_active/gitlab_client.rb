# frozen_string_literal: true

require "time"
require_relative "../helpers/http_helper"

module StillActive
  module GitlabClient
    extend self

    BASE_URI = URI("https://gitlab.com/")

    def last_commit_date(owner:, name:)
      return if owner.nil? || name.nil?

      project_id = URI.encode_www_form_component("#{owner}/#{name}")
      headers = {}
      token = StillActive.config.gitlab_token
      headers["PRIVATE-TOKEN"] = token if token

      path = "/api/v4/projects/#{project_id}/repository/commits"
      body = HttpHelper.get_json(BASE_URI, path, headers: headers, params: { per_page: 1 })
      return if body.nil? || body.empty?

      date = body.first["committed_date"]
      Time.parse(date) if date
    rescue ArgumentError
      nil
    end
  end
end
