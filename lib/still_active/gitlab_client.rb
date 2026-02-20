# frozen_string_literal: true

require "time"
require_relative "../helpers/http_helper"

module StillActive
  module GitlabClient
    extend self

    BASE_URI = URI("https://gitlab.com/")

    def archived?(owner:, name:)
      return if owner.nil? || name.nil?

      path = "/api/v4/projects/#{encode_project(owner, name)}"
      body = HttpHelper.get_json(BASE_URI, path, headers: auth_headers)
      return if body.nil?

      body["archived"] == true
    end

    def last_commit_date(owner:, name:)
      return if owner.nil? || name.nil?

      path = "/api/v4/projects/#{encode_project(owner, name)}/repository/commits"
      body = HttpHelper.get_json(BASE_URI, path, headers: auth_headers, params: { per_page: 1 })
      return if body.nil? || body.empty?

      date = body.first["committed_date"]
      Time.parse(date) if date
    rescue ArgumentError
      nil
    end

    private

    def auth_headers
      token = StillActive.config.gitlab_token
      token ? { "PRIVATE-TOKEN" => token } : {}
    end

    def encode_project(owner, name)
      URI.encode_www_form_component("#{owner}/#{name}")
    end
  end
end
