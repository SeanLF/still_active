# frozen_string_literal: true

RSpec.describe(StillActive::RepositorySignals) do
  let(:answer) { {archived: false, last_commit_date: Time.now} }

  def ask(host: "github.com", public: true) = described_class.for(host: host, owner: "o", name: "n", public: public)

  def with_token(token) = allow(StillActive.config).to(receive(:github_oauth_token).and_return(token))

  describe("a github.com repository") do
    it("asks GitHub first with a token, and says so") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return(answer))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals))

      expect(ask).to(eq(answer.merge(source: "github")))
      expect(StillActive::EcosystemsClient).not_to(have_received(:repo_signals))
    end

    it("asks ecosyste.ms first without one, and GitHub when ecosyste.ms doesn't know the repo or its archived state") do
      with_token(nil)
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return(answer))
      [{}, {last_commit_date: Time.now}].each do |unknowing|
        allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return(unknowing))
        expect(ask).to(eq(answer.merge(source: "github")))
      end
    end

    it("falls back to ecosyste.ms when GitHub can't answer, including a secondary rate limit") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_raise(StillActive::RepoSignalsUnavailable))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return(archived: true))

      expect(ask).to(eq(archived: true, source: "ecosyste.ms"))
    end

    # A forge 404s a private repository to anyone who can't see it, so its 404 is
    # "don't know", like ecosyste.ms's: ask on, and if nobody knows, unknown.
    it("reads a 404 from every service as unknown, not as 'not archived'") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return({}))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return({}))

      expect { expect(ask).to(eq(unavailable: true)) }.to(output(/no repository source answered/).to_stderr)

      allow(StillActive::GitlabClient).to(receive(:repo_signals).and_return({}))
      expect { expect(ask(host: "gitlab.com")).to(eq(unavailable: true)) }.to(output.to_stderr)
    end

    it("takes the next service's answer after a 404") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return({}))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return(archived: true))

      expect(ask).to(eq(archived: true, source: "ecosyste.ms"))
    end

    it("is unavailable, and warns, when no service can answer") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_raise(StillActive::RepoSignalsUnavailable))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return({}))

      expect { expect(ask).to(eq(unavailable: true)) }.to(output(%r{o/n: no repository source answered}).to_stderr)
    end

    # ecosyste.ms would see the name of a repository that may be private.
    it("never asks ecosyste.ms about a private-source repository, or after GitHub refused the token") do
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals))

      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_raise(StillActive::RepoSignalsUnavailable))
      expect { expect(ask(public: false)).to(eq(unavailable: true)) }.to(output.to_stderr)

      allow(StillActive::GithubClient).to(receive(:repo_signals).and_raise(StillActive::RepoAccessDenied))
      expect { expect(ask).to(eq(unavailable: true)) }.to(output.to_stderr)

      with_token(nil)
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return({}))
      expect { expect(ask(public: false)).to(eq(unavailable: true)) }.to(output.to_stderr)

      expect(StillActive::EcosystemsClient).not_to(have_received(:repo_signals))
    end
  end

  it("asks GitLab about a gitlab.com project, and Codeberg about a codeberg.org one") do
    allow(StillActive::GitlabClient).to(receive(:repo_signals).with(owner: "o", name: "n").and_return(answer))
    allow(StillActive::ForgejoClient).to(receive(:repo_signals).with(owner: "o", name: "n", host: "codeberg.org").and_return(archived: true))

    expect(ask(host: "gitlab.com")).to(eq(answer.merge(source: "gitlab")))
    expect(ask(host: "Codeberg.org")).to(eq(archived: true, source: "codeberg"))
  end

  it("has nothing to ask about an unknown host, or a missing owner") do
    expect(ask(host: "bitbucket.org")).to(eq({}))
    expect(described_class.for(host: "github.com", owner: nil, name: "n", public: true)).to(eq({}))
  end
end
