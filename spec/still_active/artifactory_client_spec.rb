# frozen_string_literal: true

require_relative "../../lib/still_active/artifactory_client"

# rubocop:disable RSpec/MultipleDescribes
RSpec.describe(StillActive::ArtifactoryClient) do
  before { StillActive.reset }

  let(:source_uri) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/" }
  let(:gem_name) { "private_gem" }
  let(:versions_api_url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/api/v1/versions/#{gem_name}.json" }
  let(:info_url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/info/#{gem_name}" }
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

    it("matches the jfrog.io suffix case-insensitively") do
      # Hostnames are case-insensitive; an uppercase host must not be misread as
      # an unqueryable private source.
      expect(described_class.artifactory_uri?("https://My-Org.JFROG.IO/artifactory/api/gems/my-repo/")).to(be(true))
    end
  end

  describe(".versions") do
    # The compact index is tried first, so every case that exercises a later
    # source needs it to answer "not served here". Cases that want it override
    # this stub.
    before { stub_request(:get, info_url).to_return(status: 404) }

    # Issue #142: Artifactory's versions API merges upstream metadata from member
    # remotes, so a gem whose real host can't answer it (Contribsys, legacy index)
    # is reported as only the rubygems.org placeholder. The installed version then
    # looks yanked. The compact index has the real list, so it must win.
    it("reports the versions the repo can actually resolve, not the merged upstream placeholder") do
      base = "https://my-org.jfrog.io/artifactory/api/gems/my-repo"
      stub_request(:get, "#{base}/info/sidekiq-pro")
        .to_return(status: 200, body: "---\n0.0.3 |checksum:40c1\n8.1.4 |checksum:39f6\n8.1.5 |checksum:e6b7\n")
      stub_request(:get, "#{base}/api/v1/versions/sidekiq-pro.json")
        .to_return(status: 200, body: [{"number" => "0.0.3", "created_at" => "2017-05-18T17:45:27.846Z"}].to_json)

      result = described_class.versions(gem_name: "sidekiq-pro", source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["8.1.5", "8.1.4", "0.0.3"]))
    end

    it("dates compact-index versions from the versions API, which carries timestamps") do
      stub_request(:get, info_url).to_return(status: 200, body: "---\n1.0.0 |checksum:aa\n2.0.0 |checksum:bb\n")
      stub_request(:get, versions_api_url).to_return(
        status: 200,
        body: [
          {"number" => "2.0.0", "created_at" => "2026-02-02T00:00:00Z"},
          {"number" => "1.0.0", "created_at" => "2025-01-01T00:00:00Z"}
        ].to_json
      )

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h.values_at("number", "created_at") })
        .to(eq([["2.0.0", "2026-02-02T00:00:00Z"], ["1.0.0", "2025-01-01T00:00:00Z"]]))
    end

    it("leaves a version undated when the versions API does not know it") do
      # A genuinely private gem: better no release date than one borrowed from a
      # public name collision. The version itself still counts.
      stub_request(:get, info_url).to_return(status: 200, body: "---\n0.0.3 |checksum:aa\n8.1.4 |checksum:bb\n")
      stub_request(:get, versions_api_url).to_return(
        status: 200,
        body: [{"number" => "0.0.3", "created_at" => "2017-05-18T17:45:27.846Z"}].to_json
      )

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.first["number"]).to(eq("8.1.4"))
      expect(result.first["created_at"]).to(be_nil)
    end

    it("does not spend a second request when the compact index already dated every version") do
      stub_request(:get, info_url)
        .to_return(status: 200, body: "---\n1.0.0 |checksum:aa,created_at:2026-01-01T00:00:00Z\n")

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.first["created_at"]).to(eq("2026-01-01T00:00:00Z"))
      expect(WebMock).not_to(have_requested(:get, versions_api_url))
    end

    it("survives a versions API that answers with something other than a list") do
      # A lockfile-derived host is untrusted input; an error object served as 200
      # must not take down the gem's whole assessment.
      stub_request(:get, info_url).to_return(status: 200, body: "---\n1.0.0 |checksum:aa\n")
      stub_request(:get, versions_api_url).to_return(
        status: 200,
        body: [["1.0.0", "not a version object"]].to_json,
        headers: {"Content-Type" => "application/json"}
      )

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["1.0.0"]))
    end

    it("returns versions from the RubyGems client when there is no compact index") do
      api_versions = [{"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z"}]
      allow(StillActive::ArtifactoryClient::CompactIndexClient).to(receive(:versions).and_return([]))
      allow(StillActive::ArtifactoryClient::RubygemsClient).to(receive(:versions).and_return(api_versions))

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq(api_versions))
    end

    it("falls back to the AQL client when the RubyGems client returns empty") do
      aql_versions = [{"number" => "7.0.0", "prerelease" => false, "created_at" => "2024-07-01T00:00:00Z"}]
      allow(StillActive::ArtifactoryClient::CompactIndexClient).to(receive(:versions).and_return([]))
      allow(StillActive::ArtifactoryClient::RubygemsClient).to(receive(:versions).and_return([]))
      allow(StillActive::ArtifactoryClient::AqlClient).to(receive(:versions).and_return(aql_versions))

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq(aql_versions))
    end

    it("returns empty on network errors") do
      allow(StillActive::ArtifactoryClient::CompactIndexClient).to(receive(:versions).and_raise(SocketError))

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq([]))
    end

    describe("authentication") do
      it("does not send the global token to a host the lockfile names but the user never opted into") do
        StillActive.config.artifactory_token = "secret-global-token"
        attacker_uri = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/"
        attacker_info = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/info/#{gem_name}"
        attacker_api = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/api/v1/versions/#{gem_name}.json"
        attacker_aql = "https://attacker.jfrog.io/artifactory/api/search/aql"
        stub_request(:get, attacker_info).to_return(status: 404)
        stub_request(:get, attacker_api).to_return(status: 404)
        stub_request(:post, attacker_aql).to_return(status: 404)

        described_class.versions(gem_name: gem_name, source_uri: attacker_uri)

        expect(WebMock).to(have_requested(:get, attacker_info).with { |req| !req.headers.key?("Authorization") })
        expect(WebMock).to(have_requested(:get, attacker_api).with { |req| !req.headers.key?("Authorization") })
        expect(WebMock).to(have_requested(:post, attacker_aql).with { |req| !req.headers.key?("Authorization") })
      end

      it("does not send the global token when artifactory_host does not match the request host") do
        StillActive.config.artifactory_token = "secret-global-token"
        StillActive.config.artifactory_host = "my-org.jfrog.io"
        attacker_uri = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/"
        attacker_info = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/info/#{gem_name}"
        attacker_api = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/api/v1/versions/#{gem_name}.json"
        attacker_aql = "https://attacker.jfrog.io/artifactory/api/search/aql"
        stub_request(:get, attacker_info).to_return(status: 404)
        stub_request(:get, attacker_api).to_return(status: 404)
        stub_request(:post, attacker_aql).to_return(status: 404)

        described_class.versions(gem_name: gem_name, source_uri: attacker_uri)

        expect(WebMock).to(have_requested(:get, attacker_info).with { |req| !req.headers.key?("Authorization") })
        expect(WebMock).to(have_requested(:get, attacker_api).with { |req| !req.headers.key?("Authorization") })
        expect(WebMock).to(have_requested(:post, attacker_aql).with { |req| !req.headers.key?("Authorization") })
      end

      it("sends the token on the compact index request, not just the versions API") do
        StillActive.config.artifactory_token = "secret-global-token"
        StillActive.config.artifactory_host = "my-org.jfrog.io"
        stub_request(:get, info_url).to_return(status: 200, body: "---\n1.0.0 |checksum:aa\n")
        stub_request(:get, versions_api_url).to_return(status: 404)

        described_class.versions(gem_name: gem_name, source_uri: source_uri)

        expect(WebMock).to(have_requested(:get, info_url)
          .with(headers: {"Authorization" => "Bearer secret-global-token"}))
      end

      it("does send the global token to the host the user named") do
        StillActive.config.artifactory_token = "secret-global-token"
        StillActive.config.artifactory_host = "my-org.jfrog.io"
        body = [{"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z"}]
        stub_request(:get, versions_api_url)
          .to_return(status: 200, body: body.to_json, headers: {"Content-Type" => "application/json"})

        described_class.versions(gem_name: gem_name, source_uri: source_uri)

        expect(WebMock).to(have_requested(:get, versions_api_url)
          .with(headers: {"Authorization" => "Bearer secret-global-token"}))
      end

      it("warns that the token will not be sent to an unauthorized host") do
        StillActive.config.artifactory_token = "secret-global-token"
        StillActive.config.artifactory_host = "my-org.jfrog.io"
        attacker_uri = "https://attacker.jfrog.io/artifactory/api/gems/some-repo/"
        attacker_base = "https://attacker.jfrog.io/artifactory/api/gems/some-repo"
        stub_request(:get, "#{attacker_base}/info/#{gem_name}").to_return(status: 404)
        stub_request(:get, "#{attacker_base}/api/v1/versions/#{gem_name}.json").to_return(status: 404)
        stub_request(:post, "https://attacker.jfrog.io/artifactory/api/search/aql").to_return(status: 404)

        expect do
          described_class.versions(gem_name: gem_name, source_uri: attacker_uri)
        end.to(output(
          /an Artifactory token is set but attacker\.jfrog\.io \(source for #{gem_name}\) is not an authorized host.*--artifactory-host=attacker\.jfrog\.io/m
        ).to_stderr)
      end

      it("URL-decodes Bundler credentials before Basic auth") do
        allow(Bundler.settings).to(receive(:[]).with(source_uri).and_return("user%40example.com:pa%3Ass"))
        allow(Bundler.settings).to(receive(:[]).with("my-org.jfrog.io").and_return(nil))
        api_body = [{"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z"}]
        stub_request(:get, versions_api_url)
          .with(headers: {"Authorization" => "Basic #{["user@example.com:pa:ss"].pack("m0")}"})
          .to_return(status: 200, body: api_body.to_json, headers: {"Content-Type" => "application/json"})

        described_class.versions(gem_name: gem_name, source_uri: source_uri)

        expect(WebMock).to(have_requested(:get, versions_api_url))
      end

      it("sends Basic auth on AQL fallback when Bundler credentials are set") do
        allow(Bundler.settings).to(receive(:[]).with(source_uri).and_return("alice:secret"))
        allow(Bundler.settings).to(receive(:[]).with("my-org.jfrog.io").and_return(nil))
        stub_request(:get, versions_api_url).to_return(status: 404)
        aql_body = {"results" => [{"name" => "private_gem-1.0.0.gem", "created" => "2025-06-01T00:00:00Z"}]}
        stub_request(:post, aql_url)
          .with(headers: {"Authorization" => /^Basic /})
          .to_return(status: 200, body: aql_body.to_json, headers: {"Content-Type" => "application/json"})

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
      body = [{"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z"}]
      stub_request(:get, versions_api_url)
        .to_return(status: 200, body: body.to_json, headers: {"Content-Type" => "application/json"})

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq(body))
    end

    it("returns empty on 404") do
      stub_request(:get, versions_api_url).to_return(status: 404)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result).to(eq([]))
    end

    it("applies provided headers to the request") do
      body = [{"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z"}]
      stub_request(:get, versions_api_url)
        .with(headers: {"Authorization" => "Bearer test-token"})
        .to_return(status: 200, body: body.to_json, headers: {"Content-Type" => "application/json"})

      described_class.versions(
        gem_name: gem_name,
        source_uri: source_uri,
        headers: {"Authorization" => "Bearer test-token"}
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
    # AQL lists cached .gem files, so `created` is when this Artifactory first
    # pulled the artifact, not when it was published. Measured against real
    # release dates the lag ran to 891 days (issue #142), and staleness and
    # libyear are computed from these timestamps, so no date beats a wrong one.
    it("does not present the artifact cache timestamp as a release date") do
      aql_body = {"results" => [{"name" => "widget-1.0.0.gem", "created" => "2024-07-01T00:00:00Z"}]}
      stub_request(:post, aql_url)
        .to_return(status: 200, body: aql_body.to_json, headers: {"Content-Type" => "application/json"})

      result = described_class.versions(gem_name: "widget", source_uri: source_uri)

      expect(result.first["number"]).to(eq("1.0.0"))
      expect(result.first["created_at"]).to(be_nil)
    end

    it("deduplicates platform variants") do
      aql_body = {
        "results" => [
          {"name" => "rails-7.0.0.gem", "created" => "2024-07-01T00:00:00Z"},
          {"name" => "rails-7.0.0-x86_64-linux.gem", "created" => "2024-07-02T00:00:00Z"},
          {"name" => "rails-6.1.0.gem", "created" => "2024-01-01T00:00:00Z"}
        ]
      }
      stub_request(:post, aql_url)
        .to_return(status: 200, body: aql_body.to_json, headers: {"Content-Type" => "application/json"})

      result = described_class.versions(gem_name: "rails", source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["7.0.0", "6.1.0"]))
    end

    it("sorts versions descending by Gem::Version") do
      aql_body = {
        "results" => [
          {"name" => "widget-1.10.0.gem", "created" => "2024-01-01T00:00:00Z"},
          {"name" => "widget-2.0.0.gem", "created" => "2024-02-01T00:00:00Z"},
          {"name" => "widget-10.0.0.gem", "created" => "2024-03-01T00:00:00Z"}
        ]
      }
      stub_request(:post, aql_url)
        .to_return(status: 200, body: aql_body.to_json, headers: {"Content-Type" => "application/json"})

      result = described_class.versions(gem_name: "widget", source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["10.0.0", "2.0.0", "1.10.0"]))
    end

    it("ignores unrelated artifacts that share a name prefix") do
      aql_body = {
        "results" => [
          {"name" => "datadog-2.0.0.gem", "created" => "2024-01-01T00:00:00Z"},
          {"name" => "datadog-ruby_core_source.gem", "created" => "2024-01-01T00:00:00Z"}
        ]
      }
      stub_request(:post, aql_url)
        .to_return(status: 200, body: aql_body.to_json, headers: {"Content-Type" => "application/json"})

      result = described_class.versions(gem_name: "datadog", source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["2.0.0"]))
    end

    it("builds well-formed JSON when the gem name contains a quote") do
      evil_gem_name = %(evil"name)
      stub_request(:post, aql_url)
        .to_return(status: 200, body: {"results" => []}.to_json, headers: {"Content-Type" => "application/json"})

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
        .with(headers: {"Authorization" => "Bearer test-token", "Content-Type" => "text/plain"})
        .to_return(status: 200, body: {"results" => []}.to_json, headers: {"Content-Type" => "application/json"})

      described_class.versions(
        gem_name: "private_gem",
        source_uri: source_uri,
        headers: {"Authorization" => "Bearer test-token"}
      )

      expect(WebMock).to(have_requested(:post, aql_url))
    end
  end
end

RSpec.describe(StillActive::ArtifactoryClient::CompactIndexClient) do
  before { StillActive.reset }

  let(:source_uri) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/" }
  let(:gem_name) { "sidekiq-pro" }
  let(:info_url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/info/#{gem_name}" }
  # Trimmed from the real Artifactory /info/sidekiq-pro output on issue #142.
  let(:info_body) do
    <<~INFO
      ---
      0.0.3 |checksum:40c1
      8.1.4 sidekiq:< 9&>= 8.1.0|checksum:39f6,ruby:>= 3.2.0
      8.1.5 sidekiq:< 9&>= 8.1.0|checksum:e6b7,ruby:>= 3.2.0
    INFO
  end

  describe(".versions") do
    it("returns every version in the compact index, newest first") do
      stub_request(:get, info_url).to_return(status: 200, body: info_body)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["8.1.5", "8.1.4", "0.0.3"]))
    end

    it("flags pre-releases, so find_version can tell them from stable releases") do
      stub_request(:get, info_url).to_return(status: 200, body: "---\n1.0.0 |checksum:aa\n2.0.0.rc1 |checksum:bb\n")

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h.values_at("number", "prerelease") })
        .to(eq([["2.0.0.rc1", true], ["1.0.0", false]]))
    end

    it("carries the declared Ruby requirement, the language-ceiling input") do
      stub_request(:get, info_url).to_return(status: 200, body: info_body)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["ruby_version"] }).to(eq([">= 3.2.0", ">= 3.2.0", nil]))
    end

    it("collapses a version's per-platform rows into one entry") do
      # /info/ lists a row per built platform; the audit reasons about versions.
      body = "---\n1.0.0 |checksum:aa\n1.0.0-arm64-darwin |checksum:bb\n1.0.0-x86_64-linux |checksum:cc\n"
      stub_request(:get, info_url).to_return(status: 200, body: body)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["1.0.0"]))
    end

    it("skips the blank lines Artifactory is known to emit in index files") do
      stub_request(:get, info_url).to_return(status: 200, body: "---\n1.0.0 |checksum:aa\n\n2.0.0 |checksum:bb\n\n")

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["2.0.0", "1.0.0"]))
    end

    it("reads the release date when the index supplies one") do
      # rubygems.org emits created_at in every /info/ row. Artifactory does not
      # (0 of 114 rows on issue #142), so this is best-effort, not a given.
      stub_request(:get, info_url)
        .to_return(status: 200, body: "---\n1.0.0 |checksum:aa,created_at:2026-06-18T15:18:58Z\n")

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.first["created_at"]).to(eq("2026-06-18T15:18:58Z"))
    end

    it("keeps the platform-independent row, which carries the full dependency set") do
      # /info/ lists platform variants before the generic row, and a native gem's
      # variants declare fewer dependencies than the ruby-platform build.
      body = "---\n1.0.0-aarch64-linux racc:~> 1.4|checksum:aa\n1.0.0 mini_portile2:~> 2.8,racc:~> 1.4|checksum:bb\n"
      stub_request(:get, info_url).to_return(status: 200, body: body)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["checksum"] }).to(eq(["bb"]))
    end

    it("returns empty when the host does not serve a compact index") do
      stub_request(:get, info_url).to_return(status: 404)

      expect(described_class.versions(gem_name: gem_name, source_uri: source_uri)).to(eq([]))
    end

    it("warns rather than silently trusting a 200 that is not a compact index") do
      # A proxy/auth wall answering /info/ with an HTML 200 parses to no versions.
      # The compact index is now the primary source, so this must be loud: a silent
      # empty result would look identical to a clean parse and hide a broken source.
      stub_request(:get, info_url).to_return(status: 200, body: "<html><body>Login required</body></html>")

      expect { described_class.versions(gem_name: gem_name, source_uri: source_uri) }
        .to(output(/my-org\.jfrog\.io.*not a .*compact index/m).to_stderr)
    end

    it("stays quiet for an all-yanked gem whose index is just the header") do
      # A valid but empty compact index (every version yanked) is "---" with no
      # rows. That is not a broken source, so it must not warn.
      stub_request(:get, info_url).to_return(status: 200, body: "---\n")

      expect { described_class.versions(gem_name: gem_name, source_uri: source_uri) }
        .not_to(output.to_stderr)
    end
  end

  # Canary. CompactIndexClient#metadata hand-parses the compact-index requirements
  # instead of using Gem::Resolver::APISet::GemParser, because GemParser mangles a
  # colon-bearing created_at until the first-colon fix in rubygems 4.0.13. The
  # rubygems bundled with our supported Rubies predates it (3.3 -> 3.5.x, 3.4 ->
  # 3.6.x). This flips red the moment a below-4.0.13 rubygems learns the fix (a
  # backport, or a raised Ruby floor shipping >= 4.0.13): at that point GemParser +
  # to_h works on our floor and #metadata can be deleted.
  it "still needs the hand-rolled compact-index metadata parse (canary)" do
    skip "rubygems #{Gem::VERSION} already has the first-colon fix" if
      Gem::Version.new(Gem::VERSION) >= Gem::Version.new("4.0.13")

    _version, _platform, _deps, requirements =
      Gem::Resolver::APISet::GemParser.new.parse("1.0.0 |created_at:2026-01-01T00:00:00Z")

    expect { requirements.to_h }.to(raise_error(ArgumentError),
      "rubygems #{Gem::VERSION} now parses a colon-bearing created_at cleanly -- replace " \
      "CompactIndexClient#metadata with GemParser + to_h and delete this canary")
  end
end
# rubocop:enable RSpec/MultipleDescribes
