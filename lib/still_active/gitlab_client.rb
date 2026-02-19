# frozen_string_literal: true

require "net/http"
require "json"
require "time"

module StillActive
  module GitlabClient
    extend self

    BASE_URI = URI("https://gitlab.com/")

    def last_commit_date(owner:, name:)
      return if owner.nil? || name.nil?

      project_id = encode("#{owner}/#{name}")
      body = get("/api/v4/projects/#{project_id}/repository/commits", per_page: 1)
      return if body.nil? || body.empty?

      date = body.first["committed_date"]
      Time.parse(date) if date
    rescue ArgumentError
      nil
    end

    private

    def get(path, **params)
      uri = BASE_URI.dup
      uri.path = path
      uri.query = URI.encode_www_form(params) unless params.empty?

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = 10
      http.read_timeout = 10

      request = Net::HTTP::Get.new(uri)
      token = StillActive.config.gitlab_token
      request["PRIVATE-TOKEN"] = token if token

      response = http.request(request)
      return unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body)
    rescue Net::OpenTimeout, Net::ReadTimeout, SocketError, Errno::ECONNREFUSED
      nil
    end

    def encode(value)
      URI.encode_www_form_component(value)
    end
  end
end
