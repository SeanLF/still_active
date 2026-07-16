# frozen_string_literal: true

RSpec.describe(StillActive::GitlabClient) do
  before { StillActive.reset }

  let(:owner) { "inkscape" }
  let(:name) { "inkscape" }
  let(:project_url) { "https://gitlab.com/api/v4/projects/#{owner}%2F#{name}" }

  def stub_project(body, headers: nil)
    stub = stub_request(:get, project_url)
    stub = stub.with(headers: headers) if headers
    stub.to_return(status: 200, body: body.to_json, headers: {"Content-Type" => "application/json"})
  end

  describe(".repo_signals") do
    it("returns archived + last-activity date from a single project call") do
      stub_project({"archived" => false, "last_activity_at" => "2026-02-15T14:30:00.000+00:00"})
      result = described_class.repo_signals(owner: owner, name: name)
      expect(result[:archived]).to(be(false))
      expect(result[:last_commit_date]).to(eq(Time.parse("2026-02-15T14:30:00.000+00:00")))
    end

    it("reports an archived project") do
      stub_project({"archived" => true, "last_activity_at" => "2026-01-01T00:00:00Z"})
      expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(true))
    end

    it("returns {} when owner is nil, without calling the API") do
      expect(described_class.repo_signals(owner: nil, name: name)).to(eq({}))
    end

    it("returns {} on timeout") do
      stub_request(:get, project_url).to_timeout
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq({}))
    end

    it("returns {} on a non-success status") do
      stub_request(:get, project_url).to_return(status: 404)
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq({}))
    end

    it("leaves the date nil when last_activity_at is absent") do
      stub_project({"archived" => false})
      expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(be_nil)
    end

    it("warns and leaves the date nil on an unparseable last_activity_at") do
      stub_project({"archived" => false, "last_activity_at" => "not-a-date"})
      expect { expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(be_nil) }
        .to(output(/could not parse repo date/).to_stderr)
    end

    it("sends the PRIVATE-TOKEN header when gitlab_token is configured") do
      StillActive.config { |config| config.gitlab_token = "glpat-test-token" }
      stub_project({"archived" => false, "last_activity_at" => "2026-02-15T14:30:00Z"}, headers: {"PRIVATE-TOKEN" => "glpat-test-token"})
      expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(false))
    ensure
      StillActive.config { |config| config.gitlab_token = nil }
    end

    it("does not send a PRIVATE-TOKEN header when gitlab_token is nil") do
      stub_request(:get, project_url)
        .with { |req| !req.headers.key?("Private-Token") }
        .to_return(status: 200, body: {"archived" => false, "last_activity_at" => "2026-02-15T14:30:00Z"}.to_json, headers: {"Content-Type" => "application/json"})
      expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(false))
    end
  end
end
