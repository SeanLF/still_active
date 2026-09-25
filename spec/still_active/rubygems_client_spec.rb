# frozen_string_literal: true

RSpec.describe(StillActive::RubygemsClient) do
  def stub_json(path, body:, status: 200)
    stub_request(:get, "https://rubygems.org#{path}")
      .to_return(status: status, headers: {"Content-Type" => "application/json"}, body: body.to_json)
  end

  describe(".versions") do
    it("returns rubygems.org's version list") do
      stub_json("/api/v1/versions/rack.json", body: [{"number" => "3.1.0"}])

      expect(described_class.versions("rack")).to(eq([{"number" => "3.1.0"}]))
    end

    it("returns [] for an unknown gem, a failed lookup, or a non-list body") do
      stub_json("/api/v1/versions/nope.json", body: {}, status: 404)
      expect(described_class.versions("nope")).to(eq([]))

      stub_json("/api/v1/versions/rack.json", body: {}, status: 503)
      expect { expect(described_class.versions("rack")).to(eq([])) }.to(output(/503/).to_stderr)

      stub_json("/api/v1/versions/odd.json", body: {"error" => "x"})
      expect(described_class.versions("odd")).to(eq([]))
    end

    it("encodes the name so it can't walk the API path") do
      stub = stub_json("/api/v1/versions/evil%2F..%2Fsecrets.json", body: [])

      described_class.versions("evil/../secrets")

      expect(stub).to(have_been_requested)
    end
  end

  # Every other source's host is allowlisted for redirects; rubygems.org has to be
  # too, or one redirect would cost every gem in the run its versions.
  it("follows a same-host redirect on rubygems.org") do
    stub_request(:get, "https://rubygems.org/api/v1/versions/rack.json")
      .to_return(status: 301, headers: {"Location" => "https://rubygems.org/api/v1/versions/rack2.json"})
    stub_json("/api/v1/versions/rack2.json", body: [{"number" => "3.1.0"}])

    expect { expect(described_class.versions("rack")).to(eq([{"number" => "3.1.0"}])) }.to(output(/redirected/).to_stderr)
  end

  describe(".info") do
    it("returns the gem's metadata, and nil when there is none") do
      stub_json("/api/v1/gems/rack.json", body: {"source_code_uri" => "https://github.com/rack/rack"})
      expect(described_class.info("rack")).to(include("source_code_uri" => "https://github.com/rack/rack"))

      stub_json("/api/v1/gems/nope.json", body: {}, status: 404)
      expect(described_class.info("nope")).to(be_nil)
    end

    # Gems.info raised on a 5xx and only NotFound was rescued, so a rubygems.org
    # blip stripped the gem of every signal. A failure is now just no metadata.
    it("returns nil rather than raising on a failed lookup") do
      stub_json("/api/v1/gems/rack.json", body: {}, status: 503)

      expect { expect(described_class.info("rack")).to(be_nil) }.to(output(/503/).to_stderr)
    end
  end

  # Artifactory serves the same API under the repo path, with the repo's credentials.
  describe(".versions under an Artifactory repo") do
    let(:base) { URI("https://my-org.jfrog.io/artifactory/api/gems/my-repo") }
    let(:url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/api/v1/versions/private_gem.json" }

    it("reads the repo's version list, sending its credentials") do
      body = [{"number" => "1.0.0"}]
      stub_request(:get, url).with(headers: {"Authorization" => "Bearer test-token"})
        .to_return(status: 200, body: body.to_json, headers: {"Content-Type" => "application/json"})

      expect(described_class.versions("private_gem", base: base, headers: {"Authorization" => "Bearer test-token"})).to(eq(body))
    end

    it("returns [] on a 404") do
      stub_request(:get, url).to_return(status: 404)

      expect(described_class.versions("private_gem", base: base)).to(eq([]))
    end
  end
end
