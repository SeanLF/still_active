# frozen_string_literal: true

RSpec.describe(StillActive::EcosystemsClient) do
  before { StillActive.reset }

  let(:owner) { "rails" }
  let(:name) { "rails" }
  let(:repo_url) { "https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/#{owner}%2F#{name}" }

  def stub_repo(body)
    stub_request(:get, repo_url)
      .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })
  end

  describe(".repo_signals") do
    it("returns archived + last-commit date from pushed_at, tokenless") do
      stub_repo({ "archived" => false, "pushed_at" => "2026-06-24T20:46:32.000Z" })
      result = described_class.repo_signals(owner: owner, name: name)
      expect(result[:archived]).to(be(false))
      expect(result[:last_commit_date]).to(eq(Time.parse("2026-06-24T20:46:32.000Z")))
    end

    it("reports an archived repo") do
      stub_repo({ "archived" => true, "pushed_at" => "2023-07-13T17:57:58.000Z" })
      expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(true))
    end

    it("omits archived (leaving it unknown) when the field is absent, rather than asserting false") do
      stub_repo({ "pushed_at" => "2026-06-24T20:46:32.000Z" })
      expect(described_class.repo_signals(owner: owner, name: name)).not_to(have_key(:archived))
    end

    it("returns {} on an unexpected non-object JSON body, without crashing") do
      stub_request(:get, repo_url)
        .to_return(status: 200, body: [1, 2].to_json, headers: { "Content-Type" => "application/json" })
      expect { expect(described_class.repo_signals(owner: owner, name: name)).to(eq({})) }.not_to(raise_error)
    end

    it("leaves the date nil on a non-string pushed_at, without crashing") do
      stub_repo({ "archived" => false, "pushed_at" => 1_234_567 })
      expect { expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(be_nil) }
        .not_to(raise_error)
    end

    it("returns {} when owner is nil, without calling the API") do
      expect(described_class.repo_signals(owner: nil, name: name)).to(eq({}))
    end

    it("returns {} on timeout") do
      stub_request(:get, repo_url).to_timeout
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq({}))
    end

    it("returns {} on a non-success status") do
      stub_request(:get, repo_url).to_return(status: 404)
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq({}))
    end

    it("leaves the date nil when pushed_at is absent or null (GitLab repos on ecosyste.ms)") do
      stub_repo({ "archived" => false, "pushed_at" => nil })
      expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(be_nil)
    end

    it("warns and leaves the date nil on an unparseable pushed_at") do
      stub_repo({ "archived" => false, "pushed_at" => "not-a-date" })
      expect { expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(be_nil) }
        .to(output(/could not parse repo date/).to_stderr)
    end

    it("identifies still_active in the User-Agent (ecosyste.ms polite pool)") do
      stub = stub_repo({ "archived" => false, "pushed_at" => "2026-06-24T20:46:32.000Z" })
        .with(headers: { "User-Agent" => /still_active/ })
      described_class.repo_signals(owner: owner, name: name)
      expect(stub).to(have_been_requested)
    end

    it("sends a mailto query param for the polite pool when an email is configured") do
      StillActive.config.ecosystems_email = "dev@example.com"
      stub = stub_request(:get, repo_url)
        .with(query: { "mailto" => "dev@example.com" })
        .to_return(status: 200,
          body: { "archived" => false, "pushed_at" => "2026-06-24T20:46:32.000Z" }.to_json,
          headers: { "Content-Type" => "application/json" })
      described_class.repo_signals(owner: owner, name: name)
      expect(stub).to(have_been_requested)
    end

    it("omits the mailto param when no email is configured (anonymous pool)") do
      stub_repo({ "archived" => false, "pushed_at" => "2026-06-24T20:46:32.000Z" })
      described_class.repo_signals(owner: owner, name: name)
      expect(a_request(:get, repo_url).with(query: hash_including("mailto"))).not_to(have_been_made)
    end
  end
end
