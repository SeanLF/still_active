# frozen_string_literal: true

require "time"
require_relative "../helpers/http_helper"

module StillActive
  module GitlabClient
    extend self

    BASE_URI = URI("https://gitlab.com/")

    # archived + last-activity date from a single project call. The project
    # object's last_activity_at matches the latest commit date to the day in
    # practice, so folding the two signals into one call halves the per-gem
    # requests. Returns {} when the project can't be read.
    def repo_signals(owner:, name:)
      return {} if owner.nil? || name.nil?

      path = "/api/v4/projects/#{encode_project(owner, name)}"
      body = HttpHelper.get_json(BASE_URI, path, headers: auth_headers)
      return {} if body.nil?

      {archived: body["archived"] == true, last_commit_date: parse_time(body["last_activity_at"], owner, name)}
    end

    private

    def parse_time(value, owner, name)
      return if value.nil?

      Time.parse(value)
    rescue ArgumentError
      warn("warning: could not parse repo date for #{owner}/#{name}: #{value.inspect}")
      nil
    end

    def auth_headers
      token = StillActive.config.gitlab_token
      token ? {"PRIVATE-TOKEN" => token} : {}
    end

    def encode_project(owner, name)
      URI.encode_www_form_component("#{owner}/#{name}")
    end
  end
end
