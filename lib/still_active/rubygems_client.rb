# frozen_string_literal: true

require_relative "helpers/http_helper"

module StillActive
  # The RubyGems JSON API this tool reads, through HttpHelper so it gets the same
  # timeouts, body cap and redirect rules as every other source. rubygems.org by
  # default; Artifactory serves the same API under a repo path, with its own
  # credentials, via `base:` and `headers:`.
  module RubygemsClient
    extend self

    BASE_URI = URI("https://rubygems.org/")

    # Every published version, newest first, as rubygems.org serves them; [] when
    # the gem doesn't exist or the lookup failed (HttpHelper has warned).
    def versions(gem_name, base: BASE_URI, headers: {})
      body = HttpHelper.get_json(base, "#{base.path.chomp("/")}/api/v1/versions/#{encode(gem_name)}.json", headers: headers)
      body.is_a?(Array) ? body : []
    end

    # The gem's metadata (homepage_uri, source_code_uri, downloads, ...), or nil.
    def info(gem_name)
      body = HttpHelper.get_json(BASE_URI, "/api/v1/gems/#{encode(gem_name)}.json")
      body if body.is_a?(Hash)
    end

    private

    def encode(value)
      URI.encode_www_form_component(value.to_s)
    end
  end
end
