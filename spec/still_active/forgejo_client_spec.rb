# frozen_string_literal: true

RSpec.describe(StillActive::ForgejoClient) do
  before { StillActive.reset }

  let(:owner) { "forgejo" }
  let(:name) { "forgejo" }
  let(:repo_url) { "https://codeberg.org/api/v1/repos/#{owner}/#{name}" }

  def stub_repo(body, headers: nil)
    stub = stub_request(:get, repo_url)
    stub = stub.with(headers: headers) if headers
    stub.to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })
  end

  describe(".repo_signals") do
    it("returns archived + last-activity date from a single repository call") do
      stub_repo({ "archived" => false, "updated_at" => "2026-02-15T14:30:00Z" })
      result = described_class.repo_signals(owner: owner, name: name)
      expect(result[:archived]).to(be(false))
      expect(result[:last_commit_date]).to(eq(Time.parse("2026-02-15T14:30:00Z")))
    end

    it("reports an archived repo") do
      stub_repo({ "archived" => true, "updated_at" => "2026-01-01T00:00:00Z" })
      expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(true))
    end

    it("returns {} when owner is nil, without calling the API") do
      expect(described_class.repo_signals(owner: nil, name: name)).to(eq({}))
    end

    it("returns {} on a non-success status") do
      stub_request(:get, repo_url).to_return(status: 404)
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq({}))
    end

    it("returns {} on timeout") do
      stub_request(:get, repo_url).to_timeout
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq({}))
    end

    it("leaves the date nil when updated_at is absent") do
      stub_repo({ "archived" => false })
      expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(be_nil)
    end

    it("warns and leaves the date nil on an unparseable updated_at") do
      stub_repo({ "archived" => false, "updated_at" => "not-a-date" })
      expect { expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(be_nil) }
        .to(output(/could not parse repo date/).to_stderr)
    end

    it("targets a custom host when given one") do
      custom = stub_request(:get, "https://git.example.org/api/v1/repos/#{owner}/#{name}")
        .to_return(status: 200, body: { "archived" => false, "updated_at" => "2026-01-01T00:00:00Z" }.to_json, headers: { "Content-Type" => "application/json" })
      described_class.repo_signals(owner: owner, name: name, host: "git.example.org")
      expect(custom).to(have_been_requested)
    end

    it("sends a token header when forgejo_token is configured") do
      StillActive.config { |config| config.forgejo_token = "fj-test-token" }
      stub = stub_repo({ "archived" => false, "updated_at" => "2026-02-15T14:30:00Z" }, headers: { "Authorization" => "token fj-test-token" })
      described_class.repo_signals(owner: owner, name: name)
      expect(stub).to(have_been_requested)
    ensure
      StillActive.config { |config| config.forgejo_token = nil }
    end

    it("does not send an Authorization header when forgejo_token is nil") do
      stub_request(:get, repo_url)
        .with { |req| !req.headers.key?("Authorization") }
        .to_return(status: 200, body: { "archived" => false, "updated_at" => "2026-02-15T14:30:00Z" }.to_json, headers: { "Content-Type" => "application/json" })
      expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(false))
    end
  end
end
