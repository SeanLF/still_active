# frozen_string_literal: true

require_relative "../../lib/still_active/source_credentials"

RSpec.describe(StillActive::SourceCredentials) do
  before { StillActive.reset }

  let(:source_uri) { "https://gems.contribsys.com/" }

  describe(".headers_for") do
    it("builds Basic auth from Bundler user:password credentials for the host") do
      allow(Bundler.settings).to(receive(:credentials_for).and_return("alice:secret"))

      expect(described_class.headers_for(source_uri))
        .to(eq("Authorization" => "Basic #{["alice:secret"].pack("m0")}"))
    end

    it("builds Bearer auth from a bare token credential") do
      allow(Bundler.settings).to(receive(:credentials_for).and_return("tok123"))

      expect(described_class.headers_for(source_uri)).to(eq("Authorization" => "Bearer tok123"))
    end

    it("URL-decodes percent-encoded Bundler credentials before Basic auth") do
      allow(Bundler.settings).to(receive(:credentials_for).and_return("user%40ex.com:pa%3Ass"))

      expect(described_class.headers_for(source_uri))
        .to(eq("Authorization" => "Basic #{["user@ex.com:pa:ss"].pack("m0")}"))
    end

    it("resolves credentials by the source host (Bundler's host-keyed store)") do
      # The security property: creds are looked up for the SOURCE host, so a
      # lockfile-named host only ever gets what the user configured for it.
      allow(Bundler.settings).to(receive(:credentials_for)) { |uri| (uri.host == "gems.contribsys.com") ? "tok" : nil }

      expect(described_class.headers_for(source_uri)).to(eq("Authorization" => "Bearer tok"))
      expect(described_class.headers_for("https://attacker.example.com/")).to(eq({}))
    end

    it("returns no header when the host has no configured credentials") do
      allow(Bundler.settings).to(receive(:credentials_for).and_return(nil))

      expect(described_class.headers_for(source_uri)).to(eq({}))
    end
  end
end
