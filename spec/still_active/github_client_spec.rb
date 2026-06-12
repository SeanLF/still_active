# frozen_string_literal: true

require_relative "../../lib/still_active/github_client"

RSpec.describe(StillActive::GithubClient) do
  let(:owner) { "rails" }
  let(:name) { "rails" }
  let(:client) { instance_double(Octokit::Client) }

  before do
    StillActive.reset
    allow(StillActive.config).to(receive(:github_client).and_return(client))
  end

  def commit_with(date)
    double(commit: double(author: double(date: date)))
  end

  describe(".archived") do
    it("returns true for an archived repo") do
      allow(client).to(receive(:repository).with("rails/rails").and_return(double(archived: true)))
      expect(described_class.archived(owner: owner, name: name)).to(be(true))
    end

    it("returns false for an active repo") do
      allow(client).to(receive(:repository).with("rails/rails").and_return(double(archived: false)))
      expect(described_class.archived(owner: owner, name: name)).to(be(false))
    end

    it("returns nil when owner is nil, without calling the API") do
      allow(client).to(receive(:repository))
      expect(described_class.archived(owner: nil, name: name)).to(be_nil)
      expect(client).not_to(have_received(:repository))
    end

    it("returns nil and warns on an Octokit error") do
      allow(client).to(receive(:repository).and_raise(Octokit::NotFound))
      expect { expect(described_class.archived(owner: owner, name: name)).to(be_nil) }
        .to(output(/archived check failed/).to_stderr)
    end
  end

  describe(".last_commit_date") do
    it("returns the commit date as a Time") do
      t = Time.now
      allow(client).to(receive(:commits).with("rails/rails", per_page: 1).and_return([commit_with(t)]))
      expect(described_class.last_commit_date(owner: owner, name: name)).to(eq(t))
    end

    it("parses a string commit date") do
      allow(client).to(receive(:commits).and_return([commit_with("2026-02-15T14:30:00Z")]))
      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_a(Time))
    end

    it("returns nil when there are no commits") do
      allow(client).to(receive(:commits).and_return([]))
      expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil)
    end

    it("returns nil when owner is nil, without calling the API") do
      allow(client).to(receive(:commits))
      expect(described_class.last_commit_date(owner: nil, name: name)).to(be_nil)
      expect(client).not_to(have_received(:commits))
    end

    it("returns nil and warns on an Octokit error") do
      allow(client).to(receive(:commits).and_raise(Octokit::TooManyRequests))
      expect { expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil) }
        .to(output(/last commit check failed/).to_stderr)
    end

    it("returns nil and warns on an unparseable date string") do
      allow(client).to(receive(:commits).and_return([commit_with("not-a-date")]))
      expect { expect(described_class.last_commit_date(owner: owner, name: name)).to(be_nil) }
        .to(output(/could not parse commit date/).to_stderr)
    end
  end
end
