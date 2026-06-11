# frozen_string_literal: true

require_relative "../../lib/still_active/artifactory_client"

# rubocop:disable RSpec/MultipleDescribes
RSpec.describe(StillActive::ArtifactoryClient) do
  before { StillActive.reset }

  let(:source_uri) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/" }
  let(:gem_name) { "private_gem" }
  let(:versions_api_url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/api/v1/versions/#{gem_name}.json" }
  let(:aql_url) { "https://my-org.jfrog.io/artifactory/api/search/aql" }

  describe(".artifactory_uri?") do
    it("returns true for a jfrog.io host") do
      expect(described_class.artifactory_uri?("https://my-org.jfrog.io/artifactory/api/gems/my-repo/")).to(be(true))
    end

    it("returns false for rubygems.org") do
      expect(described_class.artifactory_uri?("https://rubygems.org")).to(be(false))
    end

    it("returns false for an invalid URI") do
      expect(described_class.artifactory_uri?("not a uri")).to(be(false))
    end
  end

  describe(".versions") do
    it("returns versions from the RubyGems client when available") do
      api_versions = [{ "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z" }]
      allow(StillActive::ArtifactoryClient::RubygemsClient).to(receive(:versions).and_return(api_versions))

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq(api_versions))
    end

    it("falls back to the AQL client when the RubyGems client returns empty") do
      aql_versions = [{ "number" => "7.0.0", "prerelease" => false, "created_at" => "2024-07-01T00:00:00Z" }]
      allow(StillActive::ArtifactoryClient::RubygemsClient).to(receive(:versions).and_return([]))
      allow(StillActive::ArtifactoryClient::AqlClient).to(receive(:versions).and_return(aql_versions))

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq(aql_versions))
    end

    it("returns empty on network errors") do
      allow(StillActive::ArtifactoryClient::RubygemsClient).to(receive(:versions).and_raise(SocketError))

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq([]))
    end

    describe("authentication") do
      it("does not send the global token to a host the lockfile names but the user never opted into") do
        StillActive.config.artifactory_token = "secret-global-token"
        attacker_uri = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/"
        attacker_api = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/api/v1/versions/#{gem_name}.json"
        attacker_aql = "https://attacker.jfrog.io/artifactory/api/search/aql"
        stub_request(:get, attacker_api).to_return(status: 404)
        stub_request(:post, attacker_aql).to_return(status: 404)

        described_class.versions(gem_name: gem_name, source_uri: attacker_uri)

        expect(WebMock).to(have_requested(:get, attacker_api).with { |req| !req.headers.key?("Authorization") })
        expect(WebMock).to(have_requested(:post, attacker_aql).with { |req| !req.headers.key?("Authorization") })
      end

      it("does not send the global token when artifactory_host does not match the request host") do
        StillActive.config.artifactory_token = "secret-global-token"
        StillActive.config.artifactory_host  = "my-org.jfrog.io"
        attacker_uri = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/"
        attacker_api = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/api/v1/versions/#{gem_name}.json"
        attacker_aql = "https://attacker.jfrog.io/artifactory/api/search/aql"
        stub_request(:get, attacker_api).to_return(status: 404)
        stub_request(:post, attacker_aql).to_return(status: 404)

        described_class.versions(gem_name: gem_name, source_uri: attacker_uri)

        expect(WebMock).to(have_requested(:get, attacker_api).with { |req| !req.headers.key?("Authorization") })
        expect(WebMock).to(have_requested(:post, attacker_aql).with { |req| !req.headers.key?("Authorization") })
      end

      it("does send the global token to the host the user named") do
        StillActive.config.artifactory_token = "secret-global-token"
        StillActive.config.artifactory_host  = "my-org.jfrog.io"
        body = [{ "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z" }]
        stub_request(:get, versions_api_url)
          .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

        described_class.versions(gem_name: gem_name, source_uri: source_uri)

        expect(WebMock).to(have_requested(:get, versions_api_url)
          .with(headers: { "Authorization" => "Bearer secret-global-token" }))
      end

      it("warns that the token will not be sent to an unauthorized host") do
        StillActive.config.artifactory_token = "secret-global-token"
        StillActive.config.artifactory_host  = "my-org.jfrog.io"
        attacker_uri = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/"
        attacker_api = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/api/v1/versions/#{gem_name}.json"
        attacker_aql = "https://attacker.jfrog.io/artifactory/api/search/aql"
        stub_request(:get, attacker_api).to_return(status: 404)
        stub_request(:post, attacker_aql).to_return(status: 404)

        expect do
          described_class.versions(gem_name: gem_name, source_uri: attacker_uri)
        end.to(output(
          /an Artifactory token is set but attacker\.jfrog\.io \(source for #{gem_name}\) is not an authorized host.*--artifactory-host=attacker\.jfrog\.io/m,
        ).to_stderr)
      end

      it("URL-decodes Bundler credentials before Basic auth") do
        allow(Bundler.settings).to(receive(:[]).with(source_uri).and_return("user%40example.com:pa%3Ass"))
        allow(Bundler.settings).to(receive(:[]).with("my-org.jfrog.io").and_return(nil))
        api_body = [{ "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z" }]
        stub_request(:get, versions_api_url)
          .with(headers: { "Authorization" => "Basic #{["user@example.com:pa:ss"].pack("m0")}" })
          .to_return(status: 200, body: api_body.to_json, headers: { "Content-Type" => "application/json" })

        described_class.versions(gem_name: gem_name, source_uri: source_uri)

        expect(WebMock).to(have_requested(:get, versions_api_url))
      end

      it("sends Basic auth on AQL fallback when Bundler credentials are set") do
        allow(Bundler.settings).to(receive(:[]).with(source_uri).and_return("alice:secret"))
        allow(Bundler.settings).to(receive(:[]).with("my-org.jfrog.io").and_return(nil))
        stub_request(:get, versions_api_url).to_return(status: 404)
        aql_body = { "results" => [{ "name" => "private_gem-1.0.0.gem", "created" => "2025-06-01T00:00:00Z" }] }
        stub_request(:post, aql_url)
          .with(headers: { "Authorization" => /^Basic / })
          .to_return(status: 200, body: aql_body.to_json, headers: { "Content-Type" => "application/json" })

        described_class.versions(gem_name: gem_name, source_uri: source_uri)

        expect(WebMock).to(have_requested(:post, aql_url))
      end
    end
  end
end

RSpec.describe(StillActive::ArtifactoryClient::RubygemsClient) do
  before { StillActive.reset }

  let(:source_uri) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/" }
  let(:gem_name) { "private_gem" }
  let(:versions_api_url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/api/v1/versions/#{gem_name}.json" }

  describe(".versions") do
    it("returns versions on success") do
      body = [{ "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z" }]
      stub_request(:get, versions_api_url)
        .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq(body))
    end

    it("returns empty on 404") do
      stub_request(:get, versions_api_url).to_return(status: 404)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq([]))
    end

    it("applies provided headers to the request") do
      body = [{ "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z" }]
      stub_request(:get, versions_api_url)
        .with(headers: { "Authorization" => "Bearer test-token" })
        .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

      described_class.versions(
        gem_name: gem_name,
        source_uri: source_uri,
        headers: { "Authorization" => "Bearer test-token" },
      )

      expect(WebMock).to(have_requested(:get, versions_api_url))
    end
  end
end

RSpec.describe(StillActive::ArtifactoryClient::AqlClient) do
  before { StillActive.reset }

  let(:source_uri) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/" }
  let(:aql_url) { "https://my-org.jfrog.io/artifactory/api/search/aql" }

  describe(".versions") do
    it("deduplicates platform variants") do
      aql_body = {
        "results" => [
          { "name" => "rails-7.0.0.gem", "created" => "2024-07-01T00:00:00Z" },
          { "name" => "rails-7.0.0-x86_64-linux.gem", "created" => "2024-07-02T00:00:00Z" },
          { "name" => "rails-6.1.0.gem", "created" => "2024-01-01T00:00:00Z" },
        ],
      }
      stub_request(:post, aql_url)
        .to_return(status: 200, body: aql_body.to_json, headers: { "Content-Type" => "application/json" })

      result = described_class.versions(gem_name: "rails", source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["7.0.0", "6.1.0"]))
    end

    it("sorts versions descending by Gem::Version") do
      aql_body = {
        "results" => [
          { "name" => "widget-1.10.0.gem", "created" => "2024-01-01T00:00:00Z" },
          { "name" => "widget-2.0.0.gem", "created" => "2024-02-01T00:00:00Z" },
          { "name" => "widget-10.0.0.gem", "created" => "2024-03-01T00:00:00Z" },
        ],
      }
      stub_request(:post, aql_url)
        .to_return(status: 200, body: aql_body.to_json, headers: { "Content-Type" => "application/json" })

      result = described_class.versions(gem_name: "widget", source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["10.0.0", "2.0.0", "1.10.0"]))
    end

    it("ignores unrelated artifacts that share a name prefix") do
      aql_body = {
        "results" => [
          { "name" => "datadog-2.0.0.gem", "created" => "2024-01-01T00:00:00Z" },
          { "name" => "datadog-ruby_core_source.gem", "created" => "2024-01-01T00:00:00Z" },
        ],
      }
      stub_request(:post, aql_url)
        .to_return(status: 200, body: aql_body.to_json, headers: { "Content-Type" => "application/json" })

      result = described_class.versions(gem_name: "datadog", source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["2.0.0"]))
    end

    it("builds well-formed JSON when the gem name contains a quote") do
      evil_gem_name = %(evil"name)
      stub_request(:post, aql_url)
        .to_return(status: 200, body: { "results" => [] }.to_json, headers: { "Content-Type" => "application/json" })

      described_class.versions(gem_name: evil_gem_name, source_uri: source_uri)

      expect(WebMock).to(have_requested(:post, aql_url).with do |request|
        criteria = request.body[/\Aitems\.find\((.*)\)\.include/, 1]
        parsed = JSON.parse(criteria)
        expect(parsed.dig("name", "$match")).to(eq(%(evil"name-*.gem)))
        true
      end)
    end

    it("returns empty and warns when the source URI cannot be parsed") do
      bad_uri = "https://my-org.jfrog.io/no-api/here/"

      result = nil
      expect do
        result = described_class.versions(gem_name: "private_gem", source_uri: bad_uri)
      end.to(output(/unrecognized Artifactory source URL/).to_stderr)

      expect(result).to(eq([]))
      expect(WebMock).not_to(have_requested(:post, aql_url))
    end

    it("applies provided headers and sets Content-Type to text/plain") do
      stub_request(:post, aql_url)
        .with(headers: { "Authorization" => "Bearer test-token", "Content-Type" => "text/plain" })
        .to_return(status: 200, body: { "results" => [] }.to_json, headers: { "Content-Type" => "application/json" })

      described_class.versions(
        gem_name: "private_gem",
        source_uri: source_uri,
        headers: { "Authorization" => "Bearer test-token" },
      )

      expect(WebMock).to(have_requested(:post, aql_url))
    end
  end
end
# rubocop:enable RSpec/MultipleDescribes
