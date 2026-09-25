# frozen_string_literal: true

RSpec.describe(StillActive::RepositorySignals) do
  let(:answer) { {archived: false, last_commit_date: Time.now} }

  def ask(host: "github.com", public: true) = described_class.for(host: host, owner: "o", name: "n", public: public)

  def with_token(token) = allow(StillActive.config).to(receive(:github_oauth_token).and_return(token))

  def answered(from, signals = answer) = signals.merge(source: from, check: "answered")

  describe("a github.com repository") do
    it("asks GitHub first with a token, and says so") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return(answer))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals))

      expect(ask).to(eq(answered("github")))
      expect(StillActive::EcosystemsClient).not_to(have_received(:repo_signals))
    end

    it("asks ecosyste.ms first without one, and GitHub when ecosyste.ms doesn't know the repo or its archived state") do
      with_token(nil)
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return(answer))
      [{}, {last_commit_date: Time.now}].each do |unknowing|
        allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return(unknowing))
        expect(ask).to(eq(answered("github")))
      end
    end

    it("falls back to ecosyste.ms when GitHub can't answer, including a secondary rate limit") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_raise(StillActive::RepoSignalsUnavailable))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return(archived: true))

      expect(ask).to(eq(answered("ecosyste.ms", {archived: true})))
    end

    it("takes the next service's answer after a 404") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return({}))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return(archived: true))

      expect(ask).to(eq(answered("ecosyste.ms", {archived: true})))
    end

    # A forge 404s a private or deleted repository to anyone who can't see it:
    # every service not knowing it is unknowable, which a rerun won't change.
    it("is unknowable, quietly, when every service answers that it doesn't know the repository") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return({}))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return({}))

      expect { expect(ask).to(eq(check: "unknowable")) }.not_to(output.to_stderr)
    end

    # A rerun may help after a failure, so it's "failed", and warns, even if the
    # other service didn't know the repository.
    it("is failed, and warns, when a service couldn't answer and none other did") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_raise(StillActive::RepoSignalsUnavailable))
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals).and_return({}))

      expect { expect(ask).to(eq(check: "failed")) }.to(output(%r{o/n: no repository source could answer}).to_stderr)
    end

    # ecosyste.ms would see the name of a repository that may be private.
    it("never asks ecosyste.ms about a private-source repository, or after GitHub refused the token") do
      allow(StillActive::EcosystemsClient).to(receive(:repo_signals))

      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_raise(StillActive::RepoSignalsUnavailable))
      expect { expect(ask(public: false)).to(eq(check: "failed")) }.to(output.to_stderr)

      allow(StillActive::GithubClient).to(receive(:repo_signals).and_raise(StillActive::RepoAccessDenied))
      expect { expect(ask).to(eq(check: "failed")) }.to(output.to_stderr)

      with_token(nil)
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return({}))
      expect(ask(public: false)).to(eq(check: "unknowable"))

      expect(StillActive::EcosystemsClient).not_to(have_received(:repo_signals))
    end
  end

  it("asks GitLab about a gitlab.com project, and Codeberg about a codeberg.org one") do
    allow(StillActive::GitlabClient).to(receive(:repo_signals).with(owner: "o", name: "n").and_return(answer))
    allow(StillActive::ForgejoClient).to(receive(:repo_signals).with(owner: "o", name: "n", host: "codeberg.org").and_return(archived: true))

    expect(ask(host: "gitlab.com")).to(eq(answered("gitlab")))
    expect(ask(host: "Codeberg.org")).to(eq(answered("codeberg", {archived: true})))
  end

  it("is unknowable for a host no service covers, or a missing repository") do
    expect(ask(host: "go.googlesource.com")).to(eq(check: "unknowable"))
    expect(described_class.for(host: "github.com", owner: nil, name: "n", public: true)).to(eq(check: "unknowable"))
  end

  describe(".for_project") do
    it("splits a deps.dev project id, nested GitLab groups included") do
      allow(StillActive::GitlabClient).to(receive(:repo_signals).with(owner: "group/sub", name: "proj").and_return(answer))

      expect(described_class.for_project("gitlab.com/group/sub/proj", public: true)).to(eq(answered("gitlab")))
    end

    # gopkg.in redirects onto GitHub by a fixed rule.
    it("asks about a gopkg.in module as the GitHub repository it redirects to") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return(answer))

      described_class.for_project("gopkg.in/check.v1", public: true)
      described_class.for_project("gopkg.in/yaml/yaml.v3", public: true)
      described_class.for_project("gopkg.in/mgo.v2-unstable", public: true)

      expect(StillActive::GithubClient).to(have_received(:repo_signals).with(owner: "go-check", name: "check"))
      expect(StillActive::GithubClient).to(have_received(:repo_signals).with(owner: "yaml", name: "yaml"))
      expect(StillActive::GithubClient).to(have_received(:repo_signals).with(owner: "go-mgo", name: "mgo"))
    end

    it("maps a gopkg.in subpackage to its module's repository") do
      with_token("t")
      allow(StillActive::GithubClient).to(receive(:repo_signals).and_return(answer))

      described_class.for_project("gopkg.in/yaml.v3/sub", public: true)

      expect(StillActive::GithubClient).to(have_received(:repo_signals).with(owner: "go-yaml", name: "yaml"))
    end

    it("is unknowable for a project id it can't split") do
      expect(described_class.for_project(nil, public: true)).to(eq(check: "unknowable"))
      expect(described_class.for_project("gopkg.in/notversioned", public: true)).to(eq(check: "unknowable"))
    end
  end
end
