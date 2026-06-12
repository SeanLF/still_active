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

  def repo(archived:, pushed_at:)
    double(archived: archived, pushed_at: pushed_at)
  end

  describe(".repo_signals") do
    it("returns archived + last-activity date from a single repository call") do
      t = Time.now
      allow(client).to(receive(:repository).with("rails/rails").and_return(repo(archived: false, pushed_at: t)))
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq(archived: false, last_commit_date: t))
    end

    it("reports an archived repo") do
      allow(client).to(receive(:repository).and_return(repo(archived: true, pushed_at: Time.now)))
      expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(true))
    end

    it("parses a string pushed_at into a Time") do
      allow(client).to(receive(:repository).and_return(repo(archived: false, pushed_at: "2026-02-15T14:30:00Z")))
      expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(eq(Time.parse("2026-02-15T14:30:00Z")))
    end

    it("returns {} when owner is nil, without calling the API") do
      allow(client).to(receive(:repository))
      expect(described_class.repo_signals(owner: nil, name: name)).to(eq({}))
      expect(client).not_to(have_received(:repository))
    end

    it("returns {} and warns on an Octokit error") do
      allow(client).to(receive(:repository).and_raise(Octokit::NotFound))
      expect { expect(described_class.repo_signals(owner: owner, name: name)).to(eq({})) }
        .to(output(/repo signals failed/).to_stderr)
    end

    it("returns {} when the repository can't be read") do
      allow(client).to(receive(:repository).and_return(nil))
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq({}))
    end

    it("warns and leaves the date nil on an unparseable pushed_at") do
      allow(client).to(receive(:repository).and_return(repo(archived: false, pushed_at: "not-a-date")))
      expect { expect(described_class.repo_signals(owner: owner, name: name)[:last_commit_date]).to(be_nil) }
        .to(output(/could not parse repo date/).to_stderr)
    end
  end

  describe("rate-limit retry") do
    before { allow(described_class).to(receive(:sleep)) } # never actually wait in specs

    def too_many(retry_after: nil, reset: nil)
      headers = {}
      headers["retry-after"] = retry_after.to_s if retry_after
      headers["x-ratelimit-reset"] = reset.to_s if reset
      error = Octokit::TooManyRequests.new
      allow(error).to(receive(:response_headers).and_return(headers))
      error
    end

    it("waits for a near reset and retries once, then succeeds") do
      calls = 0
      allow(client).to(receive(:repository)) do
        calls += 1
        raise too_many(retry_after: 2) if calls == 1

        repo(archived: false, pushed_at: Time.now)
      end

      expect { expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(false)) }.to(output(/rate limited/).to_stderr)
      expect(described_class).to(have_received(:sleep).with(2))
    end

    it("derives the wait from x-ratelimit-reset when retry-after is absent") do
      calls = 0
      allow(client).to(receive(:repository)) do
        calls += 1
        raise too_many(reset: Time.now.to_i + 3) if calls == 1

        repo(archived: true, pushed_at: Time.now)
      end

      expect { expect(described_class.repo_signals(owner: owner, name: name)[:archived]).to(be(true)) }.to(output.to_stderr)
      expect(described_class).to(have_received(:sleep))
    end

    it("does not auto-wait when the reset is far away; warns with the token hint and returns {}") do
      allow(client).to(receive(:repository).and_raise(too_many(retry_after: 9999)))
      expect { expect(described_class.repo_signals(owner: owner, name: name)).to(eq({})) }.to(output(/set GITHUB_TOKEN/).to_stderr)
      expect(described_class).not_to(have_received(:sleep))
    end

    it("retries at most once on a persistent rate limit, then gives up with the token hint") do
      allow(client).to(receive(:repository).and_raise(too_many(retry_after: 1)))
      expect { expect(described_class.repo_signals(owner: owner, name: name)).to(eq({})) }.to(output(/waiting 1s.*set GITHUB_TOKEN/m).to_stderr)
      expect(described_class).to(have_received(:sleep).once)
    end
  end

  describe(".commits_since_release") do
    it("returns ahead_by when the v-prefixed tag resolves") do
      allow(client).to(receive(:compare).with("rails/rails", "v7.0.1", "HEAD").and_return(double(ahead_by: 42)))
      expect(described_class.commits_since_release(owner: owner, name: name, version: "7.0.1")).to(eq(42))
    end

    it("falls back to the bare version tag when the v-prefixed tag 404s") do
      allow(client).to(receive(:compare).with("rails/rails", "v7.0.1", "HEAD").and_raise(Octokit::NotFound))
      allow(client).to(receive(:compare).with("rails/rails", "7.0.1", "HEAD").and_return(double(ahead_by: 7)))
      expect(described_class.commits_since_release(owner: owner, name: name, version: "7.0.1")).to(eq(7))
    end

    it("returns nil when no tag form resolves") do
      allow(client).to(receive(:compare).and_raise(Octokit::NotFound))
      expect(described_class.commits_since_release(owner: owner, name: name, version: "7.0.1")).to(be_nil)
    end

    it("returns nil when version is nil, without calling the API") do
      allow(client).to(receive(:compare))
      expect(described_class.commits_since_release(owner: owner, name: name, version: nil)).to(be_nil)
      expect(client).not_to(have_received(:compare))
    end

    it("returns nil when owner is nil, without calling the API") do
      allow(client).to(receive(:compare))
      expect(described_class.commits_since_release(owner: nil, name: name, version: "7.0.1")).to(be_nil)
      expect(client).not_to(have_received(:compare))
    end

    it("returns nil and warns on a non-NotFound Octokit error") do
      allow(client).to(receive(:compare).and_raise(Octokit::InternalServerError))
      expect { expect(described_class.commits_since_release(owner: owner, name: name, version: "7.0.1")).to(be_nil) }
        .to(output(/unreleased-commits check failed/).to_stderr)
    end
  end
end
