# frozen_string_literal: true

RSpec.describe(StillActive::GitlabClient) do
  before { StillActive.reset }

  let(:owner) { "inkscape" }
  let(:name) { "inkscape" }
  let(:api_url) { "https://gitlab.com/api/v4/projects/#{owner}%2F#{name}/repository/commits?per_page=1" }

  describe(".archived?") do
    let(:project_url) { "https://gitlab.com/api/v4/projects/#{owner}%2F#{name}" }

    it("returns true for an archived project") do
      stub_request(:get, project_url).to_return(status: 200, body: { "archived" => true }.to_json, headers: { "Content-Type" => "application/json" })
      expect(described_class.archived?(owner: owner, name: name)).to(be(true))
    end

    it("returns false for an active project") do
      stub_request(:get, project_url).to_return(status: 200, body: { "archived" => false }.to_json, headers: { "Content-Type" => "application/json" })
      expect(described_class.archived?(owner: owner, name: name)).to(be(false))
    end

    it("returns false when owner is nil") do
      expect(described_class.archived?(owner: nil, name: name)).to(be(false))
    end

    it("returns false on timeout") do
      stub_request(:get, project_url).to_timeout
      expect(described_class.archived?(owner: owner, name: name)).to(be(false))
    end
  end

  describe(".last_commit_date") do
    it("returns a Time for a valid response") do
      body = [{ "committed_date" => "2026-02-15T14:30:00.000+00:00" }]
      stub_request(:get, api_url).to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

      result = described_class.last_commit_date(owner: owner, name: name)

      expect(result).to(be_a(Time))
      expect(result).to(eq(Time.parse("2026-02-15T14:30:00.000+00:00")))
    end

    it("returns nil when owner is nil") do
      expect(described_class.last_commit_date(owner: nil, name: name)).to(be_nil)
    end

    it("returns nil when name is nil") do
      expect(described_class.last_commit_date(owner: owner, name: nil)).to(be_nil)
    end

    it("returns nil on timeout") do
      stub_request(:get, api_url).to_timeout

      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil)
    end

    it("returns nil on connection refused") do
      stub_request(:get, api_url).to_raise(Errno::ECONNREFUSED)

      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil)
    end

    it("returns nil for an empty response body") do
      stub_request(:get, api_url).to_return(status: 200, body: "[]", headers: { "Content-Type" => "application/json" })

      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil)
    end

    it("returns nil for a non-success status") do
      stub_request(:get, api_url).to_return(status: 404)

      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil)
    end

    it("sends PRIVATE-TOKEN header when gitlab_token is configured") do
      StillActive.config { |config| config.gitlab_token = "glpat-test-token" }
      body = [{ "committed_date" => "2026-02-15T14:30:00.000+00:00" }]
      stub_request(:get, api_url)
        .with(headers: { "PRIVATE-TOKEN" => "glpat-test-token" })
        .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

      result = described_class.last_commit_date(owner: owner, name: name)

      expect(result).to(be_a(Time))
    ensure
      StillActive.config { |config| config.gitlab_token = nil }
    end

    it("does not send PRIVATE-TOKEN header when gitlab_token is nil") do
      StillActive.config { |config| config.gitlab_token = nil }
      body = [{ "committed_date" => "2026-02-15T14:30:00.000+00:00" }]
      stub_request(:get, api_url)
        .with { |req| !req.headers.key?("Private-Token") }
        .to_return(status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" })

      result = described_class.last_commit_date(owner: owner, name: name)

      expect(result).to(be_a(Time))
    end
  end
end
