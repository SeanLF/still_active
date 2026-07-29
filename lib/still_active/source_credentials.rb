# frozen_string_literal: true

require "bundler"
require "cgi"
require "uri"

module StillActive
  # Auth headers for a gem source, resolved the way Bundler itself does: from its
  # per-host credential store (`bundle config` / the `BUNDLE_<HOST>` env var).
  #
  # The store is HOST-KEYED (`credentials_for` is `self[uri.to_s] || self[uri.host]`),
  # which is the whole security property when a source URI comes from a lockfile: a
  # host the user never configured resolves to no credential, so a malicious lockfile
  # naming `attacker.example.com` cannot make still_active send another host's
  # credential there. There is deliberately NO ambient/global fallback here; the only
  # ambient token still_active holds (`--artifactory-token`) is guarded by an explicit
  # host allowlist inside ArtifactoryClient, which is the sole caller that adds it.
  module SourceCredentials
    extend self

    def headers_for(source_uri)
      auth_header(Bundler.settings.credentials_for(URI(source_uri)))
    end

    # Turns a Bundler credential string into an Authorization header: `user:pass`
    # becomes Basic (each half percent-decoded, since Bundler stores them encoded),
    # a bare token becomes Bearer. Empty/nil yields no header.
    def auth_header(credentials)
      return {} if credentials.nil? || credentials.empty?

      if credentials.include?(":")
        user, pass = credentials.split(":", 2).map { |part| CGI.unescape(part) }
        {"Authorization" => "Basic #{["#{user}:#{pass}"].pack("m0")}"}
      else
        {"Authorization" => "Bearer #{credentials}"}
      end
    end
  end
end
