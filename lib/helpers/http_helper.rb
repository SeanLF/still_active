# frozen_string_literal: true

require "net/http"
require "json"

module StillActive
  module HttpHelper
    extend self

    def get_json(base_uri, path, headers: {}, params: {})
      uri = base_uri.dup
      uri.path = path
      uri.query = URI.encode_www_form(params) unless params.empty?

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = 10
      http.read_timeout = 10

      request = Net::HTTP::Get.new(uri)
      headers.each { |key, value| request[key] = value }

      response = http.request(request)
      return unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body)
    rescue Net::OpenTimeout, Net::ReadTimeout, SocketError, Errno::ECONNREFUSED => e
      $stderr.puts("warning: #{uri.host}#{uri.path} failed: #{e.class} (#{e.message})")
      nil
    rescue JSON::ParserError => e
      $stderr.puts("warning: #{uri.host}#{uri.path} returned invalid JSON: #{e.message}")
      nil
    end
  end
end
