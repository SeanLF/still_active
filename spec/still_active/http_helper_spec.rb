# frozen_string_literal: true

require_relative "../../lib/helpers/http_helper"

RSpec.describe(StillActive::HttpHelper) do
  let(:auth) { { "Authorization" => "Bearer secret-token" } }

  # The redirect branches are the load-bearing guarantee that credentials never
  # follow a gem-source redirect onto a host they weren't issued for. A gem
  # source URL is lockfile-controlled, so this is the security boundary.
  describe(".get_json") do
    it("drops the Authorization header when a redirect crosses to a different (trusted) host") do
      stub_request(:get, "https://my-org.jfrog.io/start")
        .to_return(status: 302, headers: { "Location" => "https://api.deps.dev/landing" })
      stub_request(:get, "https://api.deps.dev/landing")
        .to_return(status: 200, body: '{"ok":true}', headers: { "Content-Type" => "application/json" })

      result = described_class.get_json(URI("https://my-org.jfrog.io"), "/start", headers: auth)

      expect(result).to(eq("ok" => true))
      expect(WebMock).to(have_requested(:get, "https://my-org.jfrog.io/start")
        .with { |req| req.headers.key?("Authorization") })
      expect(WebMock).to(have_requested(:get, "https://api.deps.dev/landing")
        .with { |req| !req.headers.key?("Authorization") })
    end

    it("does not follow a redirect to an untrusted host, and never sends the token there") do
      stub_request(:get, "https://my-org.jfrog.io/start")
        .to_return(status: 302, headers: { "Location" => "https://evil.example.com/steal" })
      evil = stub_request(:get, "https://evil.example.com/steal")

      result = described_class.get_json(URI("https://my-org.jfrog.io"), "/start", headers: auth)

      expect(result).to(be_nil)
      expect(evil).not_to(have_been_requested)
    end

    it("keeps the Authorization header on a same-host redirect") do
      stub_request(:get, "https://api.deps.dev/a")
        .to_return(status: 302, headers: { "Location" => "https://api.deps.dev/b" })
      stub_request(:get, "https://api.deps.dev/b")
        .to_return(status: 200, body: "{}", headers: { "Content-Type" => "application/json" })

      described_class.get_json(URI("https://api.deps.dev"), "/a", headers: auth)

      expect(WebMock).to(have_requested(:get, "https://api.deps.dev/b")
        .with { |req| req.headers.key?("Authorization") })
    end

    it("keeps the Authorization header when the redirect spells out the default port") do
      # https://host and https://host:443 are the same origin; same_origin? must
      # treat the implicit and explicit default port as equal.
      stub_request(:get, "https://api.deps.dev/a")
        .to_return(status: 302, headers: { "Location" => "https://api.deps.dev:443/b" })
      stub_request(:get, "https://api.deps.dev:443/b")
        .to_return(status: 200, body: "{}", headers: { "Content-Type" => "application/json" })

      described_class.get_json(URI("https://api.deps.dev"), "/a", headers: auth)

      expect(WebMock).to(have_requested(:get, "https://api.deps.dev:443/b")
        .with { |req| req.headers.key?("Authorization") })
    end

    it("drops the Authorization header when a same-host redirect changes the port") do
      # Same host, different origin: a different port is a different service and
      # must not inherit a token issued for the original origin.
      stub_request(:get, "https://api.deps.dev/a")
        .to_return(status: 302, headers: { "Location" => "https://api.deps.dev:8443/b" })
      stub_request(:get, "https://api.deps.dev:8443/b")
        .to_return(status: 200, body: "{}", headers: { "Content-Type" => "application/json" })

      described_class.get_json(URI("https://api.deps.dev"), "/a", headers: auth)

      expect(WebMock).to(have_requested(:get, "https://api.deps.dev:8443/b")
        .with { |req| !req.headers.key?("Authorization") })
    end

    it("refuses a redirect that downgrades the scheme to http and never sends the token there") do
      stub_request(:get, "https://api.deps.dev/a")
        .to_return(status: 302, headers: { "Location" => "http://api.deps.dev/b" })
      downgrade = stub_request(:get, "http://api.deps.dev/b")

      result = described_class.get_json(URI("https://api.deps.dev"), "/a", headers: auth)

      expect(result).to(be_nil)
      expect(downgrade).not_to(have_been_requested)
    end

    it("gives up after MAX_REDIRECTS and returns nil") do
      stub_request(:get, "https://api.deps.dev/1")
        .to_return(status: 302, headers: { "Location" => "https://github.com/2" })
      stub_request(:get, "https://github.com/2")
        .to_return(status: 302, headers: { "Location" => "https://gitlab.com/3" })
      stub_request(:get, "https://gitlab.com/3")
        .to_return(status: 302, headers: { "Location" => "https://api.deps.dev/4" })
      landing = stub_request(:get, "https://api.deps.dev/4")
        .to_return(status: 200, body: "{}")

      result = described_class.get_json(URI("https://api.deps.dev"), "/1", headers: auth)

      expect(result).to(be_nil)
      # The loop runs MAX_REDIRECTS (3) times, so the fourth hop is never requested.
      expect(landing).not_to(have_been_requested)
    end

    it("returns nil instead of raising when a 3xx response has no Location header") do
      stub_request(:get, "https://api.deps.dev/x").to_return(status: 302)

      result = nil
      expect { result = described_class.get_json(URI("https://api.deps.dev"), "/x", headers: auth) }
        .not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of raising when a 3xx Location is malformed") do
      stub_request(:get, "https://api.deps.dev/x")
        .to_return(status: 302, headers: { "Location" => "http://[bad" })

      result = nil
      expect { result = described_class.get_json(URI("https://api.deps.dev"), "/x", headers: auth) }
        .not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of parsing a response body over the size cap") do
      stub_const("StillActive::HttpHelper::MAX_BODY_BYTES", 50)
      # Valid JSON, but larger than the cap: the cap must win before parsing.
      stub_request(:get, "https://api.deps.dev/big")
        .to_return(status: 200, body: "[#{"0," * 100}0]", headers: { "Content-Type" => "application/json" })

      expect(described_class.get_json(URI("https://api.deps.dev"), "/big")).to(be_nil)
    end
  end

  # post_json carries the AQL fallback, so it must enforce the same boundary as
  # the versions GET.
  describe(".post_json") do
    it("drops the Authorization header when a redirect crosses to a different (trusted) host") do
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql")
        .to_return(status: 302, headers: { "Location" => "https://api.deps.dev/landing" })
      stub_request(:post, "https://api.deps.dev/landing")
        .to_return(status: 200, body: '{"results":[]}', headers: { "Content-Type" => "application/json" })

      result = described_class.post_json(
        URI("https://my-org.jfrog.io"),
        "/api/search/aql",
        body: "items.find({})",
        headers: auth,
      )

      expect(result).to(eq("results" => []))
      expect(WebMock).to(have_requested(:post, "https://my-org.jfrog.io/api/search/aql")
        .with { |req| req.headers.key?("Authorization") })
      expect(WebMock).to(have_requested(:post, "https://api.deps.dev/landing")
        .with { |req| !req.headers.key?("Authorization") })
    end

    it("does not follow a redirect to an untrusted host, and never sends the token there") do
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql")
        .to_return(status: 302, headers: { "Location" => "https://evil.example.com/steal" })
      evil = stub_request(:post, "https://evil.example.com/steal")

      result = described_class.post_json(
        URI("https://my-org.jfrog.io"),
        "/api/search/aql",
        body: "items.find({})",
        headers: auth,
      )

      expect(result).to(be_nil)
      expect(evil).not_to(have_been_requested)
    end

    it("returns nil instead of raising when a 3xx response has no Location header") do
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql").to_return(status: 302)

      result = nil
      expect do
        result = described_class.post_json(
          URI("https://my-org.jfrog.io"),
          "/api/search/aql",
          body: "items.find({})",
          headers: auth,
        )
      end.not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of raising when a 3xx Location is malformed") do
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql")
        .to_return(status: 302, headers: { "Location" => "http://[bad" })

      result = nil
      expect do
        result = described_class.post_json(
          URI("https://my-org.jfrog.io"),
          "/api/search/aql",
          body: "items.find({})",
          headers: auth,
        )
      end.not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of parsing a response body over the size cap") do
      stub_const("StillActive::HttpHelper::MAX_BODY_BYTES", 50)
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql")
        .to_return(status: 200, body: "[#{"0," * 100}0]", headers: { "Content-Type" => "application/json" })

      result = described_class.post_json(
        URI("https://my-org.jfrog.io"),
        "/api/search/aql",
        body: "items.find({})",
      )

      expect(result).to(be_nil)
    end
  end
end
