# frozen_string_literal: true

RSpec.describe(StillActive::Config) do
  before { StillActive.reset }

  describe("github_oauth_token discovery") do
    around do |example|
      original = ENV.to_hash
      ENV.delete("GITHUB_TOKEN")
      ENV.delete("GH_TOKEN")
      example.run
    ensure
      ENV.clear
      original.each { |k, v| ENV[k] = v }
    end

    it("uses GITHUB_TOKEN when set") do
      ENV["GITHUB_TOKEN"] = "ghp_from_env"
      expect(described_class.new.github_oauth_token).to(eq("ghp_from_env"))
    end

    it("falls back to GH_TOKEN when GITHUB_TOKEN is absent") do
      ENV["GH_TOKEN"] = "ghp_from_gh_env"
      expect(described_class.new.github_oauth_token).to(eq("ghp_from_gh_env"))
    end

    it("prefers GITHUB_TOKEN over GH_TOKEN") do
      ENV["GITHUB_TOKEN"] = "ghp_winner"
      ENV["GH_TOKEN"] = "ghp_loser"
      expect(described_class.new.github_oauth_token).to(eq("ghp_winner"))
    end

    it("falls back to `gh auth token` when both env vars are absent") do
      status = instance_double(Process::Status, success?: true)
      allow(Open3).to(receive(:capture3).with("gh", "auth", "token").and_return(["ghp_from_gh_cli\n", "", status]))
      expect(described_class.new.github_oauth_token).to(eq("ghp_from_gh_cli"))
    end

    it("returns nil silently when gh CLI is not installed (no warning)") do
      allow(Open3).to(receive(:capture3).with("gh", "auth", "token").and_raise(Errno::ENOENT))
      expect { expect(described_class.new.github_oauth_token).to(be_nil) }.not_to(output.to_stderr)
    end

    it("warns and returns nil when gh CLI exits non-zero (auth broken)") do
      status = instance_double(Process::Status, success?: false)
      allow(Open3).to(receive(:capture3).with("gh", "auth", "token").and_return(["", "not logged in", status]))
      expect { expect(described_class.new.github_oauth_token).to(be_nil) }
        .to(output(/`gh auth token` failed: not logged in/).to_stderr)
    end

    it("warns and returns nil when gh CLI prints an empty token") do
      status = instance_double(Process::Status, success?: true)
      allow(Open3).to(receive(:capture3).with("gh", "auth", "token").and_return(["\n", "", status]))
      expect { expect(described_class.new.github_oauth_token).to(be_nil) }
        .to(output(/`gh auth token` returned empty output/).to_stderr)
    end

    it("treats an empty GITHUB_TOKEN as unset (common in fork PRs)") do
      ENV["GITHUB_TOKEN"] = ""
      ENV["GH_TOKEN"] = "ghp_fallback"
      expect(described_class.new.github_oauth_token).to(eq("ghp_fallback"))
    end

    it("treats an empty GH_TOKEN as unset and falls through to gh CLI") do
      ENV["GH_TOKEN"] = ""
      status = instance_double(Process::Status, success?: true)
      allow(Open3).to(receive(:capture3).with("gh", "auth", "token").and_return(["ghp_from_cli\n", "", status]))
      expect(described_class.new.github_oauth_token).to(eq("ghp_from_cli"))
    end

    it("does NOT shell out to gh when GITHUB_TOKEN is set") do
      ENV["GITHUB_TOKEN"] = "ghp_env"
      allow(Open3).to(receive(:capture3))
      described_class.new.github_oauth_token
      expect(Open3).not_to(have_received(:capture3))
    end

    it("does not shell out at Config.new — only on first read of github_oauth_token") do
      allow(Open3).to(receive(:capture3))
      described_class.new
      expect(Open3).not_to(have_received(:capture3))
    end
  end
end
