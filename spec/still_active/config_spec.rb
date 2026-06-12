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

  describe("forgejo_token discovery") do
    around do |example|
      original = ENV.to_hash
      ENV.delete("STILL_ACTIVE_FORGEJO_TOKEN")
      ENV.delete("CODEBERG_TOKEN")
      example.run
    ensure
      ENV.clear
      original.each { |k, v| ENV[k] = v }
    end

    it("uses STILL_ACTIVE_FORGEJO_TOKEN when set") do
      ENV["STILL_ACTIVE_FORGEJO_TOKEN"] = "fj_from_env"
      expect(described_class.new.forgejo_token).to(eq("fj_from_env"))
    end

    it("accepts CODEBERG_TOKEN as an alias") do
      ENV["CODEBERG_TOKEN"] = "fj_from_codeberg"
      expect(described_class.new.forgejo_token).to(eq("fj_from_codeberg"))
    end

    it("prefers STILL_ACTIVE_FORGEJO_TOKEN over CODEBERG_TOKEN") do
      ENV["STILL_ACTIVE_FORGEJO_TOKEN"] = "fj_primary"
      ENV["CODEBERG_TOKEN"] = "fj_alias"
      expect(described_class.new.forgejo_token).to(eq("fj_primary"))
    end

    it("treats an empty token as unset") do
      ENV["STILL_ACTIVE_FORGEJO_TOKEN"] = ""
      expect(described_class.new.forgejo_token).to(be_nil)
    end

    it("returns nil when no token env var is set (anonymous reads)") do
      expect(described_class.new.forgejo_token).to(be_nil)
    end
  end

  describe("gitlab_token discovery") do
    around do |example|
      original = ENV.to_hash
      ENV.delete("GITLAB_TOKEN")
      example.run
    ensure
      ENV.clear
      original.each { |k, v| ENV[k] = v }
    end

    it("uses GITLAB_TOKEN when set") do
      ENV["GITLAB_TOKEN"] = "glpat_from_env"
      expect(described_class.new.gitlab_token).to(eq("glpat_from_env"))
    end

    it("treats an empty GITLAB_TOKEN as unset") do
      ENV["GITLAB_TOKEN"] = ""
      status = instance_double(Process::Status, success?: true)
      allow(Open3).to(receive(:capture3).with("glab", "auth", "status", "--hostname=gitlab.com", "--show-token").and_return(["", "Token: glpat_from_glab\n", status]))
      expect(described_class.new.gitlab_token).to(eq("glpat_from_glab"))
    end

    it("falls back to `glab auth status --hostname=gitlab.com --show-token` when env var absent") do
      status = instance_double(Process::Status, success?: true)
      # glab prints "Token: <value>" on stderr (not stdout).
      allow(Open3).to(receive(:capture3).with("glab", "auth", "status", "--hostname=gitlab.com", "--show-token").and_return(["", "Token: glpat_from_glab\n", status]))
      expect(described_class.new.gitlab_token).to(eq("glpat_from_glab"))
    end

    it("returns nil silently when glab CLI is not installed") do
      allow(Open3).to(receive(:capture3).with("glab", "auth", "status", "--hostname=gitlab.com", "--show-token").and_raise(Errno::ENOENT))
      expect { expect(described_class.new.gitlab_token).to(be_nil) }.not_to(output.to_stderr)
    end

    it("warns and returns nil when glab CLI exits non-zero") do
      status = instance_double(Process::Status, success?: false)
      allow(Open3).to(receive(:capture3).with("glab", "auth", "status", "--hostname=gitlab.com", "--show-token").and_return(["", "not logged in", status]))
      expect { expect(described_class.new.gitlab_token).to(be_nil) }
        .to(output(/`glab auth status` failed: not logged in/).to_stderr)
    end

    it("warns and returns nil when glab output is missing the Token line") do
      status = instance_double(Process::Status, success?: true)
      allow(Open3).to(receive(:capture3).with("glab", "auth", "status", "--hostname=gitlab.com", "--show-token").and_return(["", "Logged in to gitlab.com\n", status]))
      expect { expect(described_class.new.gitlab_token).to(be_nil) }
        .to(output(/`glab auth status` did not return a Token line/).to_stderr)
    end

    it("does not shell out at Config.new — only on first read of gitlab_token") do
      allow(Open3).to(receive(:capture3))
      described_class.new
      expect(Open3).not_to(have_received(:capture3))
    end

    it("does NOT shell out to glab when GITLAB_TOKEN is set") do
      ENV["GITLAB_TOKEN"] = "glpat_env"
      allow(Open3).to(receive(:capture3))
      described_class.new.gitlab_token
      expect(Open3).not_to(have_received(:capture3))
    end
  end

  it("defaults alternatives to false") do
    expect(described_class.new.alternatives).to(be(false))
  end

  describe("gemfile_path discovery") do
    it("returns Bundler.default_gemfile when a Gemfile is reachable") do
      allow(Bundler).to(receive(:default_gemfile).and_return(Pathname.new("/proj/Gemfile")))
      expect(described_class.new.gemfile_path).to(eq("/proj/Gemfile"))
    end

    it("falls back to ./Gemfile when no Gemfile is reachable (GemfileNotFound)") do
      allow(Bundler).to(receive(:default_gemfile).and_raise(Bundler::GemfileNotFound))
      expect(described_class.new.gemfile_path).to(eq(File.join(Dir.pwd, "Gemfile")))
    end

    it("does not invoke Bundler.default_gemfile at Config.new") do
      allow(Bundler).to(receive(:default_gemfile))
      described_class.new
      expect(Bundler).not_to(have_received(:default_gemfile))
    end

    it("honours an explicit path set via the writer") do
      config = described_class.new
      config.gemfile_path = "/elsewhere/Gemfile"
      expect(config.gemfile_path).to(eq("/elsewhere/Gemfile"))
    end

    it("does not call Bundler.default_gemfile when an explicit path is set first") do
      allow(Bundler).to(receive(:default_gemfile))
      config = described_class.new
      config.gemfile_path = "/elsewhere/Gemfile"
      config.gemfile_path
      expect(Bundler).not_to(have_received(:default_gemfile))
    end
  end
end
