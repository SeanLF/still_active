# frozen_string_literal: true

require_relative "../../lib/still_active/helpers/http_helper"

RSpec.describe(StillActive::HttpHelper) do
  let(:auth) { {"Authorization" => "Bearer secret-token"} }

  # The redirect branches are the load-bearing guarantee that credentials never
  # follow a gem-source redirect onto a host they weren't issued for. A gem
  # source URL is lockfile-controlled, so this is the security boundary.
  describe(".get_json") do
    it("drops the Authorization header when a redirect crosses to a different (trusted) host") do
      stub_request(:get, "https://my-org.jfrog.io/start")
        .to_return(status: 302, headers: {"Location" => "https://api.deps.dev/landing"})
      stub_request(:get, "https://api.deps.dev/landing")
        .to_return(status: 200, body: '{"ok":true}', headers: {"Content-Type" => "application/json"})

      result = described_class.get_json(URI("https://my-org.jfrog.io"), "/start", headers: auth)

      expect(result).to(eq("ok" => true))
      expect(WebMock).to(have_requested(:get, "https://my-org.jfrog.io/start")
        .with { |req| req.headers.key?("Authorization") })
      expect(WebMock).to(have_requested(:get, "https://api.deps.dev/landing")
        .with { |req| !req.headers.key?("Authorization") })
    end

    it("does not follow a redirect to an untrusted host, and never sends the token there") do
      stub_request(:get, "https://my-org.jfrog.io/start")
        .to_return(status: 302, headers: {"Location" => "https://evil.example.com/steal"})
      evil = stub_request(:get, "https://evil.example.com/steal")

      result = described_class.get_json(URI("https://my-org.jfrog.io"), "/start", headers: auth)

      expect(result).to(be_nil)
      expect(evil).not_to(have_been_requested)
    end

    it("keeps the Authorization header on a same-host redirect") do
      stub_request(:get, "https://api.deps.dev/a")
        .to_return(status: 302, headers: {"Location" => "https://api.deps.dev/b"})
      stub_request(:get, "https://api.deps.dev/b")
        .to_return(status: 200, body: "{}", headers: {"Content-Type" => "application/json"})

      described_class.get_json(URI("https://api.deps.dev"), "/a", headers: auth)

      expect(WebMock).to(have_requested(:get, "https://api.deps.dev/b")
        .with { |req| req.headers.key?("Authorization") })
    end

    it("keeps the Authorization header when the redirect spells out the default port") do
      # https://host and https://host:443 are the same origin; same_origin? must
      # treat the implicit and explicit default port as equal.
      stub_request(:get, "https://api.deps.dev/a")
        .to_return(status: 302, headers: {"Location" => "https://api.deps.dev:443/b"})
      stub_request(:get, "https://api.deps.dev:443/b")
        .to_return(status: 200, body: "{}", headers: {"Content-Type" => "application/json"})

      described_class.get_json(URI("https://api.deps.dev"), "/a", headers: auth)

      expect(WebMock).to(have_requested(:get, "https://api.deps.dev:443/b")
        .with { |req| req.headers.key?("Authorization") })
    end

    it("drops the Authorization header when a same-host redirect changes the port") do
      # Same host, different origin: a different port is a different service and
      # must not inherit a token issued for the original origin.
      stub_request(:get, "https://api.deps.dev/a")
        .to_return(status: 302, headers: {"Location" => "https://api.deps.dev:8443/b"})
      stub_request(:get, "https://api.deps.dev:8443/b")
        .to_return(status: 200, body: "{}", headers: {"Content-Type" => "application/json"})

      described_class.get_json(URI("https://api.deps.dev"), "/a", headers: auth)

      expect(WebMock).to(have_requested(:get, "https://api.deps.dev:8443/b")
        .with { |req| !req.headers.key?("Authorization") })
    end

    it("refuses a redirect that downgrades the scheme to http and never sends the token there") do
      stub_request(:get, "https://api.deps.dev/a")
        .to_return(status: 302, headers: {"Location" => "http://api.deps.dev/b"})
      downgrade = stub_request(:get, "http://api.deps.dev/b")

      result = described_class.get_json(URI("https://api.deps.dev"), "/a", headers: auth)

      expect(result).to(be_nil)
      expect(downgrade).not_to(have_been_requested)
    end

    it("gives up after MAX_REDIRECTS and returns nil") do
      stub_request(:get, "https://api.deps.dev/1")
        .to_return(status: 302, headers: {"Location" => "https://github.com/2"})
      stub_request(:get, "https://github.com/2")
        .to_return(status: 302, headers: {"Location" => "https://gitlab.com/3"})
      stub_request(:get, "https://gitlab.com/3")
        .to_return(status: 302, headers: {"Location" => "https://api.deps.dev/4"})
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
        .to_return(status: 302, headers: {"Location" => "http://[bad"})

      result = nil
      expect { result = described_class.get_json(URI("https://api.deps.dev"), "/x", headers: auth) }
        .not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of raising on a TLS handshake failure (OpenSSL::SSL::SSLError)") do
      stub_request(:get, "https://api.deps.dev/x").to_raise(OpenSSL::SSL::SSLError.new("handshake failure"))

      result = nil
      expect { result = described_class.get_json(URI("https://api.deps.dev"), "/x", headers: auth) }.not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of raising when the host is unreachable (an Errno::* / SystemCallError)") do
      stub_request(:get, "https://api.deps.dev/x").to_raise(Errno::EHOSTUNREACH)

      result = nil
      expect { result = described_class.get_json(URI("https://api.deps.dev"), "/x", headers: auth) }.not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of parsing a response body over the size cap") do
      stub_const("StillActive::HttpHelper::MAX_BODY_BYTES", 50)
      # Valid JSON, but larger than the cap: the cap must win before parsing.
      stub_request(:get, "https://api.deps.dev/big")
        .to_return(status: 200, body: "[#{"0," * 100}0]", headers: {"Content-Type" => "application/json"})

      expect(described_class.get_json(URI("https://api.deps.dev"), "/big")).to(be_nil)
    end
  end

  # post_json carries the AQL fallback, so it must enforce the same boundary as
  # the versions GET.
  describe(".post_json") do
    it("drops the Authorization header when a redirect crosses to a different (trusted) host") do
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql")
        .to_return(status: 302, headers: {"Location" => "https://api.deps.dev/landing"})
      stub_request(:post, "https://api.deps.dev/landing")
        .to_return(status: 200, body: '{"results":[]}', headers: {"Content-Type" => "application/json"})

      result = described_class.post_json(
        URI("https://my-org.jfrog.io"),
        "/api/search/aql",
        body: "items.find({})",
        headers: auth
      )

      expect(result).to(eq("results" => []))
      expect(WebMock).to(have_requested(:post, "https://my-org.jfrog.io/api/search/aql")
        .with { |req| req.headers.key?("Authorization") })
      expect(WebMock).to(have_requested(:post, "https://api.deps.dev/landing")
        .with { |req| !req.headers.key?("Authorization") })
    end

    it("does not follow a redirect to an untrusted host, and never sends the token there") do
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql")
        .to_return(status: 302, headers: {"Location" => "https://evil.example.com/steal"})
      evil = stub_request(:post, "https://evil.example.com/steal")

      result = described_class.post_json(
        URI("https://my-org.jfrog.io"),
        "/api/search/aql",
        body: "items.find({})",
        headers: auth
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
          headers: auth
        )
      end.not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of raising when a 3xx Location is malformed") do
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql")
        .to_return(status: 302, headers: {"Location" => "http://[bad"})

      result = nil
      expect do
        result = described_class.post_json(
          URI("https://my-org.jfrog.io"),
          "/api/search/aql",
          body: "items.find({})",
          headers: auth
        )
      end.not_to(raise_error)
      expect(result).to(be_nil)
    end

    it("returns nil instead of parsing a response body over the size cap") do
      stub_const("StillActive::HttpHelper::MAX_BODY_BYTES", 50)
      stub_request(:post, "https://my-org.jfrog.io/api/search/aql")
        .to_return(status: 200, body: "[#{"0," * 100}0]", headers: {"Content-Type" => "application/json"})

      result = described_class.post_json(
        URI("https://my-org.jfrog.io"),
        "/api/search/aql",
        body: "items.find({})"
      )

      expect(result).to(be_nil)
    end
  end

  # A caller that must not read a failure as "nothing there" (advisories) asks for
  # strict mode: a 404 is still an answer, anything else that isn't one raises.
  describe("strict mode") do
    let(:base) { URI("https://api.deps.dev") }

    def get
      described_class.get_json(base, "/x", strict: true)
    end

    it("returns the body, and nil for a 404") do
      stub_request(:get, "https://api.deps.dev/x").to_return(status: 200, body: "{}", headers: {"Content-Type" => "application/json"})
      expect(get).to(eq({}))

      stub_request(:get, "https://api.deps.dev/x").to_return(status: 404)
      expect(get).to(be_nil)
    end

    it("raises Unavailable for a 5xx, a 429, a timeout, garbled JSON, or a refused redirect") do
      [
        -> { stub_request(:get, "https://api.deps.dev/x").to_return(status: 503) },
        -> { stub_request(:get, "https://api.deps.dev/x").to_return(status: 429) },
        -> { stub_request(:get, "https://api.deps.dev/x").to_timeout },
        -> { stub_request(:get, "https://api.deps.dev/x").to_return(status: 200, body: "not json") },
        -> { stub_request(:get, "https://api.deps.dev/x").to_return(status: 302, headers: {"Location" => "https://evil.example.com/"}) }
      ].each do |stub|
        WebMock.reset!
        stub.call
        expect { get }.to(raise_error(described_class::Unavailable).and(output.to_stderr))
      end
    end

    it("leaves the default mode returning nil on failure") do
      stub_request(:get, "https://api.deps.dev/x").to_return(status: 503)

      expect { expect(described_class.get_json(base, "/x")).to(be_nil) }.to(output.to_stderr)
    end
  end

  # One TLS handshake per host, not per request: a connection goes back to the pool
  # only after a fully read success, since an early return leaves bytes unread.
  describe("connection reuse") do
    let(:base) { URI("https://api.deps.dev") }

    def ok(path) = stub_request(:get, "https://api.deps.dev#{path}").to_return(status: 200, body: "{}", headers: {"Content-Type" => "application/json"})

    it("reuses one connection for sequential requests to a host") do
      ok("/a")
      ok("/b")
      allow(Net::HTTP).to(receive(:new).and_call_original)

      described_class.get_json(base, "/a")
      described_class.get_json(base, "/b")

      expect(Net::HTTP).to(have_received(:new).once)
    end

    it("reuses after a 404 (read to the end), but not after an error left mid-response") do
      stub_request(:get, "https://api.deps.dev/missing").to_return(status: 404)
      stub_request(:get, "https://api.deps.dev/down").to_return(status: 503)
      ok("/after")
      allow(Net::HTTP).to(receive(:new).and_call_original)

      described_class.get_json(base, "/missing")
      expect { described_class.get_json(base, "/down") }.to(output.to_stderr)
      described_class.get_json(base, "/after")

      expect(Net::HTTP).to(have_received(:new).twice)
    end
  end

  # A rate limit that says when to come back gets one bounded retry.
  describe("Retry-After") do
    let(:base) { URI("https://api.deps.dev") }

    before { allow(described_class).to(receive(:sleep)) }

    it("waits the stated seconds and retries once on a 429") do
      stub_request(:get, "https://api.deps.dev/x")
        .to_return(status: 429, headers: {"Retry-After" => "2"}).then
        .to_return(status: 200, body: '{"ok":true}', headers: {"Content-Type" => "application/json"})

      result = nil
      expect { result = described_class.get_json(base, "/x") }.to(output(/429.*retrying in 2s/).to_stderr)

      expect(result).to(eq("ok" => true))
      expect(described_class).to(have_received(:sleep).with(2))
    end

    it("doesn't spend a redirect on the retry") do
      stub_request(:get, "https://api.deps.dev/x").to_return(status: 429, headers: {"Retry-After" => "1"}).then
        .to_return(status: 301, headers: {"Location" => "https://api.deps.dev/y"})
      stub_request(:get, "https://api.deps.dev/y").to_return(status: 301, headers: {"Location" => "https://api.deps.dev/z"})
      stub_request(:get, "https://api.deps.dev/z").to_return(status: 200, body: '{"ok":true}', headers: {"Content-Type" => "application/json"})

      result = nil
      expect { result = described_class.get_json(base, "/x") }.to(output.to_stderr)
      expect(result).to(eq("ok" => true))
    end

    it("gives up after one retry, and doesn't wait on a missing, dated or overlong Retry-After") do
      stub_request(:get, "https://api.deps.dev/x").to_return(status: 429, headers: {"Retry-After" => "1"})
      expect { described_class.get_json(base, "/x") }.to(output.to_stderr)
      expect(a_request(:get, "https://api.deps.dev/x")).to(have_been_made.twice)

      [{}, {"Retry-After" => "Wed, 21 Oct 2026 07:28:00 GMT"}, {"Retry-After" => "3600"}].each do |headers|
        WebMock.reset!
        stub_request(:get, "https://api.deps.dev/x").to_return(status: 429, headers: headers)
        expect { described_class.get_json(base, "/x") }.to(output.to_stderr)
        expect(a_request(:get, "https://api.deps.dev/x")).to(have_been_made.once)
      end
    end
  end
end
