# frozen_string_literal: true

RSpec.describe(StillActive::ForgejoClient) do
  before { StillActive.reset }

  let(:owner) { "forgejo" }
  let(:name) { "forgejo" }
  let(:repo_url) { "https://codeberg.org/api/v1/repos/#{owner}/#{name}" }
  let(:commits_url) { "https://codeberg.org/api/v1/repos/#{owner}/#{name}/commits" }

  describe(".archived") do
    it("returns true for an archived repo") do
      stub_request(:get, repo_url).to_return(status: 200, body: { "archived" => true }.to_json, headers: { "Content-Type" => "application/json" })
      expect(described_class.archived(owner: owner, name: name)).to(be(true))
    end

    it("returns false for an active repo") do
      stub_request(:get, repo_url).to_return(status: 200, body: { "archived" => false }.to_json, headers: { "Content-Type" => "application/json" })
      expect(described_class.archived(owner: owner, name: name)).to(be(false))
    end

    it("returns nil when owner is nil") do
      expect(described_class.archived(owner: nil, name: name)).to(be_nil)
    end

    it("returns nil on a non-success status") do
      stub_request(:get, repo_url).to_return(status: 404)
      expect(described_class.archived(owner: owner, name: name)).to(be_nil)
    end

    it("targets a custom host when given one") do
      custom = stub_request(:get, "https://git.example.org/api/v1/repos/#{owner}/#{name}")
        .to_return(status: 200, body: { "archived" => false }.to_json, headers: { "Content-Type" => "application/json" })
      described_class.archived(owner: owner, name: name, host: "git.example.org")
      expect(custom).to(have_been_requested)
    end
  end

  describe(".last_commit_date") do
    let(:body) { [{ "commit" => { "committer" => { "date" => "2026-02-15T14:30:00Z" }, "author" => { "date" => "2026-01-01T00:00:00Z" } } }] }

    it("returns the committer date as a Time") do
      stub_request(:get, commits_url).with(query: hash_including("limit" => "1"))
        .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

      result = described_class.last_commit_date(owner: owner, name: name)

      expect(result).to(eq(Time.parse("2026-02-15T14:30:00Z")))
    end

    it("falls back to the author date when committer date is absent") do
      author_only = [{ "commit" => { "author" => { "date" => "2026-01-01T00:00:00Z" } } }]
      stub_request(:get, commits_url).with(query: hash_including("limit" => "1"))
        .to_return(status: 200, body: author_only.to_json, headers: { "Content-Type" => "application/json" })

      expect(described_class.last_commit_date(owner: owner, name: name)).to(eq(Time.parse("2026-01-01T00:00:00Z")))
    end

    it("returns nil when owner is nil") do
      expect(described_class.last_commit_date(owner: nil, name: name)).to(be_nil)
    end

    it("returns nil for an empty response body") do
      stub_request(:get, commits_url).with(query: hash_including("limit" => "1")).to_return(status: 200, body: "[]", headers: { "Content-Type" => "application/json" })
      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil)
    end

    it("returns nil on timeout") do
      stub_request(:get, commits_url).with(query: hash_including("limit" => "1")).to_timeout
      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil)
    end

    it("returns nil and warns on an unparseable date string") do
      bad = [{ "commit" => { "committer" => { "date" => "not-a-date" } } }]
      stub_request(:get, commits_url).with(query: hash_including("limit" => "1"))
        .to_return(status: 200, body: bad.to_json, headers: { "Content-Type" => "application/json" })

      expect { expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil) }
        .to(output(/could not parse commit date/).to_stderr)
    end

    it("sends a token header when forgejo_token is configured") do
      StillActive.config { |config| config.forgejo_token = "fj-test-token" }
      stub = stub_request(:get, commits_url)
        .with(query: hash_including("limit" => "1"), headers: { "Authorization" => "token fj-test-token" })
        .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

      described_class.last_commit_date(owner: owner, name: name)

      expect(stub).to(have_been_requested)
    ensure
      StillActive.config { |config| config.forgejo_token = nil }
    end

    it("does not send an Authorization header when forgejo_token is nil") do
      stub_request(:get, commits_url)
        .with(query: hash_including("limit" => "1")) { |req| !req.headers.key?("Authorization") }
        .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_a(Time))
    end
  end
end
