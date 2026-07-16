# frozen_string_literal: true

require "tempfile"
require "json"

RSpec.describe(StillActive::BotContext) do
  describe(".detect") do
    it("returns nil when there is no bot signal") do
      expect(described_class.detect(env: {}, head_subject: "Refactor the parser")).to(be_nil)
    end

    # The Renovate subject pattern must not fire on ordinary "Update X to Y" commits.
    ["Update CI to use Node 24", "Update README to mention SARIF", "Update Ruby to 3.4", "Bump version to 1.5.0"].each do |subject|
      it("does not false-positive on the human commit #{subject.inspect}") do
        expect(described_class.detect(env: {}, head_subject: subject)).to(be_nil)
      end
    end

    context("when the GitHub event payload names the PR author") do
      def event_file(login)
        f = Tempfile.new(["event", ".json"])
        f.write({"pull_request" => {"user" => {"login" => login, "type" => "Bot"}}}.to_json)
        f.flush
        f
      end

      it("detects Dependabot from pull_request.user.login") do
        f = event_file("dependabot[bot]")
        result = described_class.detect(env: {"GITHUB_EVENT_PATH" => f.path}, head_subject: nil)
        expect(result[:bot]).to(eq("dependabot"))
      ensure
        f.close!
      end

      it("detects Renovate from pull_request.user.login") do
        f = event_file("renovate[bot]")
        result = described_class.detect(env: {"GITHUB_EVENT_PATH" => f.path}, head_subject: nil)
        expect(result[:bot]).to(eq("renovate"))
      ensure
        f.close!
      end

      # The event author is the authoritative signal: it must win even when
      # GITHUB_ACTOR is a human who re-ran or pushed to the bot's PR.
      it("trusts the PR author over a human GITHUB_ACTOR") do
        f = event_file("dependabot[bot]")
        result = described_class.detect(
          env: {"GITHUB_EVENT_PATH" => f.path, "GITHUB_ACTOR" => "octocat"},
          head_subject: "Bump rack from 2.0.0 to 2.0.6"
        )
        expect(result[:bot]).to(eq("dependabot"))
      ensure
        f.close!
      end

      it("falls through when the event file is missing or unreadable") do
        result = described_class.detect(env: {"GITHUB_EVENT_PATH" => "/no/such/event.json", "GITHUB_ACTOR" => "renovate[bot]"}, head_subject: nil)
        expect(result[:bot]).to(eq("renovate"))
      end

      # A payload that parses but is the wrong shape must not crash the run.
      ["[]", '{"pull_request":[]}', '{"pull_request":{"user":"oops"}}'].each do |malformed|
        it("falls through (no crash) on a wrong-shape payload #{malformed.inspect}") do
          f = Tempfile.new(["event", ".json"])
          f.write(malformed)
          f.flush
          result = nil
          expect { result = described_class.detect(env: {"GITHUB_EVENT_PATH" => f.path}, head_subject: nil) }.not_to(raise_error)
          expect(result).to(be_nil)
        ensure
          f.close!
        end
      end
    end

    context("when GITHUB_ACTOR is set") do
      it("detects Dependabot") do
        result = described_class.detect(env: {"GITHUB_ACTOR" => "dependabot[bot]"}, head_subject: nil)
        expect(result[:bot]).to(eq("dependabot"))
      end

      it("detects Renovate") do
        result = described_class.detect(env: {"GITHUB_ACTOR" => "renovate[bot]"}, head_subject: nil)
        expect(result[:bot]).to(eq("renovate"))
      end
    end

    context("when the branch has a bot prefix") do
      it("detects Dependabot from a dependabot/ branch") do
        result = described_class.detect(env: {"GITHUB_HEAD_REF" => "dependabot/bundler/rack-2.0.6"}, head_subject: nil)
        expect(result[:bot]).to(eq("dependabot"))
      end

      it("detects Renovate from a renovate/ branch") do
        result = described_class.detect(env: {"GITHUB_HEAD_REF" => "renovate/rack-2.x"}, head_subject: nil)
        expect(result[:bot]).to(eq("renovate"))
      end
    end

    context("when only the commit subject signals a bot") do
      it("detects Dependabot's default (unprefixed, capitalized) subject and extracts the bump") do
        result = described_class.detect(env: {}, head_subject: "Bump rack from 2.0.0 to 2.0.6")
        expect(result[:bot]).to(eq("dependabot"))
        expect(result[:bumps]).to(eq([{gem: "rack", from: "2.0.0", to: "2.0.6"}]))
      end

      it("detects Dependabot's conventional-commit prefixed subject") do
        result = described_class.detect(env: {}, head_subject: "build(deps): bump rack from 2.0.0 to 2.0.6")
        expect(result[:bot]).to(eq("dependabot"))
        expect(result[:bumps]).to(eq([{gem: "rack", from: "2.0.0", to: "2.0.6"}]))
      end

      it("detects Renovate's default subject (no from version available)") do
        result = described_class.detect(env: {}, head_subject: "Update dependency rack to v2.0.6")
        expect(result[:bot]).to(eq("renovate"))
        expect(result[:bumps]).to(eq([{gem: "rack", from: nil, to: "2.0.6"}]))
      end

      it("detects Renovate's conventional-commit prefixed subject") do
        result = described_class.detect(env: {}, head_subject: "chore(deps): update dependency rack to v2.0.6")
        expect(result[:bot]).to(eq("renovate"))
      end
    end

    # Dependabot's commit-message.prefix / prefix-development / include:scope configs
    # change the subject prefix. Detection still fires via GITHUB_ACTOR; extraction
    # must tolerate any prefix/scope around the "bump X from Y to Z" skeleton.
    context("when Dependabot is configured with a custom commit-message prefix or scope") do
      [
        "chore(deps): bump rack from 2.0.0 to 2.0.6",
        "chore: bump rack from 2.0.0 to 2.0.6",
        "deps: bump rack from 2.0.0 to 2.0.6",
        "build(deps-dev): bump rack from 2.0.0 to 2.0.6"
      ].each do |subject|
        it("still extracts the bump from #{subject.inspect}") do
          result = described_class.detect(env: {"GITHUB_ACTOR" => "dependabot[bot]"}, head_subject: subject)
          expect(result[:bumps]).to(eq([{gem: "rack", from: "2.0.0", to: "2.0.6"}]))
        end
      end
    end

    context("when Renovate is configured with a custom commit-message prefix") do
      it("extracts the bump from a prefixed Renovate subject") do
        result = described_class.detect(env: {"GITHUB_ACTOR" => "renovate[bot]"}, head_subject: "chore(deps): update dependency rack to v2.0.6")
        expect(result[:bumps]).to(eq([{gem: "rack", from: nil, to: "2.0.6"}]))
      end
    end

    context("when the bot is detected but the subject does not parse (e.g. grouped update)") do
      it("returns the bot with no bumps") do
        result = described_class.detect(
          env: {"GITHUB_HEAD_REF" => "dependabot/bundler/the-bundler-group"},
          head_subject: "Bump the bundler group with 3 updates"
        )
        expect(result[:bot]).to(eq("dependabot"))
        expect(result[:bumps]).to(eq([]))
      end
    end

    it("prefers GITHUB_ACTOR over branch and subject") do
      result = described_class.detect(
        env: {"GITHUB_ACTOR" => "dependabot[bot]", "GITHUB_HEAD_REF" => "renovate/x"},
        head_subject: "Update dependency rack to v2.0.6"
      )
      expect(result[:bot]).to(eq("dependabot"))
    end
  end

  describe(".summary") do
    it("describes a single Dependabot bump with from and to") do
      summary = described_class.summary({bot: "dependabot", bumps: [{gem: "rack", from: "2.0.0", to: "2.0.6"}]})
      expect(summary).to(eq("Dependabot bump: rack 2.0.0 → 2.0.6"))
    end

    it("describes a single Renovate update without a from version") do
      summary = described_class.summary({bot: "renovate", bumps: [{gem: "rack", from: nil, to: "2.0.6"}]})
      expect(summary).to(eq("Renovate update: rack → 2.0.6"))
    end

    it("summarizes multiple bumps by count") do
      summary = described_class.summary({bot: "dependabot", bumps: [{gem: "a"}, {gem: "b"}]})
      expect(summary).to(eq("Dependabot: 2 dependency updates"))
    end

    it("falls back to a generic line when there are no parsed bumps") do
      summary = described_class.summary({bot: "dependabot", bumps: []})
      expect(summary).to(eq("Dependabot dependency update"))
    end
  end
end
