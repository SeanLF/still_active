# frozen_string_literal: true

require "net/http"
require "json"

module StillActive
  module HttpHelper
    TRUSTED_HOSTS = ["github.com", "gitlab.com", "api.deps.dev", "endoflife.date", "rubygems.pkg.github.com"].freeze
    MAX_REDIRECTS = 3

    extend self

    def get_json(base_uri, path, headers: {}, params: {})
      uri = base_uri.dup
      uri.path = path
      uri.query = URI.encode_www_form(params) unless params.empty?

      MAX_REDIRECTS.times do
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 10
        http.read_timeout = 10

        request = Net::HTTP::Get.new(uri)
        headers.each { |key, value| request[key] = value }

        response = http.request(request)

        if response.is_a?(Net::HTTPRedirection)
          redirect_uri = uri + response["Location"]
          unless TRUSTED_HOSTS.include?(redirect_uri.host)
            $stderr.puts("warning: #{uri.host}#{uri.path} redirected to untrusted host #{redirect_uri.host}, skipping")
            return
          end
          $stderr.puts("warning: #{uri.host}#{uri.path} redirected to #{redirect_uri.host}#{redirect_uri.path} (stale metadata?)")
          headers = {} if redirect_uri.host != uri.host
          uri = redirect_uri
          next
        end

        unless response.is_a?(Net::HTTPSuccess)
          $stderr.puts("warning: #{uri.host}#{uri.path} returned HTTP #{response.code}") unless response.is_a?(Net::HTTPNotFound)
          return
        end

        return JSON.parse(response.body)
      end

      $stderr.puts("warning: #{uri.host}#{uri.path} too many redirects")
      nil
    rescue Net::OpenTimeout, Net::ReadTimeout, SocketError, Errno::ECONNREFUSED, Errno::ECONNRESET => e
      $stderr.puts("warning: #{uri.host}#{uri.path} failed: #{e.class} (#{e.message})")
      nil
    rescue JSON::ParserError => e
      $stderr.puts("warning: #{uri.host}#{uri.path} returned invalid JSON: #{e.message}")
      nil
    end
  end
end
