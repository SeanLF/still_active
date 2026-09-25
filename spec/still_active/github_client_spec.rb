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

    # A 404 is GitHub answering that the repo isn't there; anything else is no
    # answer, and a missing archived flag must not read as "not archived".
    it("returns {} for a repo GitHub says doesn't exist") do
      allow(client).to(receive(:repository).and_raise(Octokit::NotFound))
      expect(described_class.repo_signals(owner: owner, name: name)).to(eq({}))
    end

    it("asks ecosyste.ms when GitHub can't answer, and raises when neither can") do
      allow(client).to(receive(:repository).and_raise(Octokit::InternalServerError))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).with(owner: owner, name: name).and_return(archived: true))

      expect { expect(described_class.repo_signals(owner: owner, name: name)).to(eq(archived: true)) }
        .to(output(/repo signals failed.*asking ecosyste\.ms/).to_stderr)

      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_raise(StillActive::RepoSignalsUnavailable))
      expect { described_class.repo_signals(owner: owner, name: name) }
        .to(raise_error(StillActive::RepoSignalsUnavailable).and(output.to_stderr))
    end

    # ecosyste.ms 404s a repo it hasn't crawled, and every private one: after
    # GitHub failed, that's nobody answering, not "not archived".
    it("reads a fallback that doesn't know the repo, or its archived state, as unavailable") do
      allow(client).to(receive(:repository).and_raise(Octokit::InternalServerError))
      [{}, {last_commit_date: Time.now}].each do |answer|
        allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return(answer))
        expect { described_class.repo_signals(owner: owner, name: name) }
          .to(raise_error(StillActive::RepoSignalsUnavailable).and(output.to_stderr))
      end
    end

    # A private repo's name must not go to a third party: no fallback for a
    # dependency that didn't come from a public registry, nor on a 401/403.
    it("doesn't ask ecosyste.ms about a repo that may be private") do
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals))

      allow(client).to(receive(:repository).and_raise(Octokit::InternalServerError))
      expect { described_class.repo_signals(owner: owner, name: name, public: false) }
        .to(raise_error(StillActive::RepoSignalsUnavailable).and(output.to_stderr))

      [Octokit::Unauthorized, Octokit::Forbidden].each do |error|
        allow(client).to(receive(:repository).and_raise(error))
        expect { described_class.repo_signals(owner: owner, name: name) }
          .to(raise_error(StillActive::RepoSignalsUnavailable).and(output.to_stderr))
      end
      expect(StillActive::EcosystemsClient).not_to(have_received(:repo_signals))
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

    # A rate-limited run once read an archived repo as healthy: the limit left
    # archived blank, and a blank archived isn't "archived".
    it("doesn't wait out a far reset; asks ecosyste.ms instead") do
      allow(client).to(receive(:repository).and_raise(too_many(retry_after: 9999)))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return(archived: true))

      expect { expect(described_class.repo_signals(owner: owner, name: name)).to(eq(archived: true)) }.to(output(/rate limited/).to_stderr)
      expect(described_class).not_to(have_received(:sleep))
    end

    it("retries at most once on a persistent rate limit, then asks ecosyste.ms") do
      allow(client).to(receive(:repository).and_raise(too_many(retry_after: 1)))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_raise(StillActive::RepoSignalsUnavailable))

      expect { described_class.repo_signals(owner: owner, name: name) }
        .to(raise_error(StillActive::RepoSignalsUnavailable).and(output(/waiting 1s/).to_stderr))
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
