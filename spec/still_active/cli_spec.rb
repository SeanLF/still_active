# frozen_string_literal: true

require "tempfile"

RSpec.describe(StillActive::CLI) do
  subject(:cli) { described_class.new }

  let(:recent_date) { Time.now }
  let(:old_date) { Time.new(Time.now.year - 2, 1, 1) }
  let(:ancient_date) { Time.new(Time.now.year - 5, 1, 1) }

  let(:workflow_result) { {} }

  before do
    allow(StillActive::Workflow).to(receive_messages(call: workflow_result, ruby_freshness: nil))
    allow($stdout).to(receive(:puts))
    # No bot context by default — keeps tests off the git subprocesses BotContext shells to.
    allow(StillActive::BotContext).to(receive(:detect).and_return(nil))
    StillActive.reset
  end

  def gem_data(last_commit_date:)
    {
      last_commit_date: last_commit_date,
      latest_version_release_date: nil,
      latest_pre_release_version_release_date: nil,
      version_used: "1.0.0",
      latest_version: "1.0.0",
      latest_pre_release_version: nil,
      scorecard_score: nil,
      vulnerability_count: nil,
    }
  end

  describe("--baseline") do
    let(:workflow_result) { { "rails" => gem_data(last_commit_date: recent_date) } }

    before { allow($stdout).to(receive(:tty?).and_return(false)) }

    def write_baseline(path, gems)
      File.write(path, {
        schema_version: 1,
        tool: { name: "still_active", version: "1.4.0" },
        generated_at: "2026-05-01T00:00:00Z",
        gems: gems,
      }.to_json)
    end

    it("emits a markdown diff and exits 0 when there are no regressions") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      Tempfile.create(["baseline", ".json"]) do |f|
        write_baseline(f.path, { "rails" => { version_used: "1.0.0", archived: false, vulnerability_count: 0 } })
        expect { cli.run(["--gems=rails", "--baseline=#{f.path}"]) }.not_to(raise_error)
      end
      expect(captured).to(include("## still_active diff"))
    end

    it("exits 1 when a regression is detected") do
      allow($stdout).to(receive(:puts))
      Tempfile.create(["baseline", ".json"]) do |f|
        # Baseline has no rails; current has rails archived → newly added archived gem = regression
        write_baseline(f.path, {})
        # Override workflow_result for this test
        allow(StillActive::Workflow).to(receive(:call).and_return({
          "rails" => gem_data(last_commit_date: recent_date).merge(archived: true),
        }))
        expect { cli.run(["--gems=rails", "--baseline=#{f.path}"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    it("exits 2 with a friendly error on invalid JSON baseline") do
      allow($stderr).to(receive(:puts))
      Tempfile.create(["baseline", ".json"]) do |f|
        File.write(f.path, "not valid json {")
        expect { cli.run(["--gems=rails", "--baseline=#{f.path}"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) })
      end
    end

    it("exits 2 with a friendly error on unsupported schema_version") do
      allow($stderr).to(receive(:puts))
      Tempfile.create(["baseline", ".json"]) do |f|
        File.write(f.path, '{"schema_version":999,"gems":{}}')
        expect { cli.run(["--gems=rails", "--baseline=#{f.path}"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) })
      end
    end

    it("supersedes --sarif and --json when all are given") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      Tempfile.create(["baseline", ".json"]) do |f|
        write_baseline(f.path, { "rails" => { version_used: "1.0.0", archived: false } })
        cli.run(["--gems=rails", "--json", "--sarif=-", "--baseline=#{f.path}"])
      end
      # Output should be markdown diff, not SARIF or wrapped JSON
      expect(captured).to(include("## still_active diff"))
      expect(captured).not_to(include('"version": "2.1.0"'))
      expect(captured).not_to(include('"schema_version"'))
    end
  end

  describe("--sarif") do
    let(:workflow_result) { { "rails" => gem_data(last_commit_date: ancient_date).merge(archived: true) } }
    let(:fake_lockfile) { "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (1.0)\n" }

    before { allow($stdout).to(receive(:tty?).and_return(false)) }

    it("writes SARIF to the default file when --sarif is bare") do
      Dir.mktmpdir do |dir|
        Dir.chdir(dir) do
          File.write("Gemfile", "")
          File.write("Gemfile.lock", fake_lockfile)
          StillActive.config.gemfile_path = "#{dir}/Gemfile"
          cli.run(["--gems=rails", "--sarif"])
          expect(File.exist?("still_active.sarif.json")).to(be(true))
          payload = JSON.parse(File.read("still_active.sarif.json"))
          expect(payload["version"]).to(eq("2.1.0"))
        end
      end
    end

    it("writes SARIF to stdout when --sarif=-") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      Dir.mktmpdir do |dir|
        File.write("#{dir}/Gemfile", "")
        File.write("#{dir}/Gemfile.lock", fake_lockfile)
        StillActive.config.gemfile_path = "#{dir}/Gemfile"
        cli.run(["--gems=rails", "--sarif=-"])
      end
      expect(captured).to(include('"version": "2.1.0"'))
    end

    it("exits 2 when Gemfile.lock is missing") do
      Dir.mktmpdir do |dir|
        StillActive.config.gemfile_path = "#{dir}/Gemfile"
        allow($stderr).to(receive(:puts))
        expect { cli.run(["--gems=rails", "--sarif=-"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) })
      end
    end

    it("resolves gems.rb to gems.locked (Bundler alternate convention)") do
      Dir.mktmpdir do |dir|
        File.write("#{dir}/gems.rb", "")
        File.write("#{dir}/gems.locked", fake_lockfile)
        StillActive.config.gemfile_path = "#{dir}/gems.rb"
        captured = nil
        allow($stdout).to(receive(:puts)) { |arg| captured = arg }
        cli.run(["--gems=rails", "--sarif=-"])
        expect(captured).to(include('"version": "2.1.0"'))
      end
    end

    it("overrides --json when both are passed") do
      Dir.mktmpdir do |dir|
        File.write("#{dir}/Gemfile", "")
        File.write("#{dir}/Gemfile.lock", fake_lockfile)
        StillActive.config.gemfile_path = "#{dir}/Gemfile"
        captured = nil
        allow($stdout).to(receive(:puts)) { |arg| captured = arg }
        cli.run(["--gems=rails", "--json", "--sarif=-"])
        # Output should be SARIF, not the JSON envelope
        expect(captured).to(include('"version": "2.1.0"'))
        expect(captured).not_to(include('"schema_version"'))
      end
    end
  end

  describe("JSON envelope") do
    let(:workflow_result) { { "rails" => gem_data(last_commit_date: recent_date) } }
    let(:ruby_info) { { version: "3.4.0", eol: false } }

    before do
      allow($stdout).to(receive(:tty?).and_return(false))
      allow(StillActive::Workflow).to(receive(:ruby_freshness).and_return(ruby_info))
    end

    it("wraps gems and ruby in a versioned envelope") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--gems=rails", "--json"])
      payload = JSON.parse(captured)
      expect(payload).to(include("schema_version" => 1))
      expect(payload.dig("tool", "name")).to(eq("still_active"))
      expect(payload.dig("tool", "version")).to(eq(StillActive::VERSION))
      expect(payload["generated_at"]).to(match(/\A\d{4}-\d{2}-\d{2}T/))
      expect(payload.dig("gems", "rails")).to(be_a(Hash))
      expect(payload["ruby"]).to(eq("version" => "3.4.0", "eol" => false))
    end

    it("omits ruby key when ruby info is nil") do
      allow(StillActive::Workflow).to(receive(:ruby_freshness).and_return(nil))
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--gems=rails", "--json"])
      payload = JSON.parse(captured)
      expect(payload).not_to(have_key("ruby"))
      expect(payload).to(have_key("gems"))
    end

    it("includes alternatives in the gem entry when present") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      allow(StillActive::Workflow).to(receive(:call).and_return(
        "paperclip" => gem_data(last_commit_date: ancient_date).merge(archived: true, alternatives: ["shrine", "carrierwave"]),
      ))
      cli.run(["--gems=paperclip", "--json"])
      payload = JSON.parse(captured)
      expect(payload.dig("gems", "paperclip", "alternatives")).to(eq(["shrine", "carrierwave"]))
    end
  end

  describe("output format auto-detection") do
    let(:workflow_result) { { "rails" => gem_data(last_commit_date: recent_date) } }

    context("when stdout is a TTY") do
      before { allow($stdout).to(receive(:tty?).and_return(true)) }

      it("outputs terminal format by default") do
        cli.run(["--gems=rails"])
        expect($stdout).to(have_received(:puts).with(include("ok")))
      end
    end

    context("when stdout is not a TTY") do
      before { allow($stdout).to(receive(:tty?).and_return(false)) }

      it("outputs JSON by default") do
        cli.run(["--gems=rails"])
        expect($stdout).to(have_received(:puts).with(include('"rails"')))
      end
    end

    context("when format is explicitly set") do
      before { allow($stdout).to(receive(:tty?).and_return(true)) }

      it("respects --json even on a TTY") do
        cli.run(["--gems=rails", "--json"])
        expect($stdout).to(have_received(:puts).with(include('"rails"')))
      end
    end
  end

  describe("--fail-if-critical") do
    context("when a gem has critical activity warning") do
      let(:workflow_result) { { "stale_gem" => gem_data(last_commit_date: ancient_date) } }

      it("exits 1") do
        expect { cli.run(["--gems=stale_gem", "--json", "--fail-if-critical"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    context("when no gems have critical activity warning") do
      let(:workflow_result) { { "fresh_gem" => gem_data(last_commit_date: recent_date) } }

      it("exits 0") do
        expect { cli.run(["--gems=fresh_gem", "--json", "--fail-if-critical"]) }
          .not_to(raise_error)
      end
    end
  end

  describe("--ignore") do
    context("when ignored gem has critical activity") do
      let(:workflow_result) do
        {
          "stale_gem" => gem_data(last_commit_date: ancient_date),
          "fresh_gem" => gem_data(last_commit_date: recent_date),
        }
      end

      it("does not exit 1 when only ignored gems are critical") do
        expect { cli.run(["--gems=stale_gem,fresh_gem", "--json", "--fail-if-critical", "--ignore=stale_gem"]) }
          .not_to(raise_error)
      end
    end

    context("when non-ignored gem has critical activity") do
      let(:workflow_result) do
        {
          "stale_gem" => gem_data(last_commit_date: ancient_date),
          "fresh_gem" => gem_data(last_commit_date: recent_date),
        }
      end

      it("exits 1 for non-ignored critical gem") do
        expect { cli.run(["--gems=stale_gem,fresh_gem", "--json", "--fail-if-critical", "--ignore=fresh_gem"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end
  end

  describe("archived repo with --fail-if-critical") do
    context("when a gem's repo is archived") do
      let(:workflow_result) do
        { "dead_gem" => gem_data(last_commit_date: recent_date).merge(archived: true) }
      end

      it("exits 1") do
        expect { cli.run(["--gems=dead_gem", "--json", "--fail-if-critical"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end
  end

  describe("--fail-if-vulnerable") do
    context("when a gem has vulnerabilities") do
      let(:workflow_result) do
        {
          "vuln_gem" => gem_data(last_commit_date: recent_date).merge(
            vulnerability_count: 2,
            vulnerabilities: [{ id: "CVE-1", cvss3_score: 9.1 }, { id: "CVE-2", cvss3_score: 5.0 }],
          ),
        }
      end

      it("exits 1") do
        expect { cli.run(["--gems=vuln_gem", "--json", "--fail-if-vulnerable"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    context("when no gems have vulnerabilities") do
      let(:workflow_result) do
        { "safe_gem" => gem_data(last_commit_date: recent_date).merge(vulnerability_count: 0, vulnerabilities: []) }
      end

      it("exits 0") do
        expect { cli.run(["--gems=safe_gem", "--json", "--fail-if-vulnerable"]) }
          .not_to(raise_error)
      end
    end

    context("when ignored gem has vulnerabilities") do
      let(:workflow_result) do
        {
          "vuln_gem" => gem_data(last_commit_date: recent_date).merge(
            vulnerability_count: 1,
            vulnerabilities: [{ id: "CVE-1", cvss3_score: 9.0 }],
          ),
          "safe_gem" => gem_data(last_commit_date: recent_date).merge(vulnerability_count: 0, vulnerabilities: []),
        }
      end

      it("does not exit 1") do
        expect { cli.run(["--gems=vuln_gem,safe_gem", "--json", "--fail-if-vulnerable", "--ignore=vuln_gem"]) }
          .not_to(raise_error)
      end
    end

    context("with severity threshold") do
      let(:workflow_result) do
        {
          "low_vuln_gem" => gem_data(last_commit_date: recent_date).merge(
            vulnerability_count: 1,
            vulnerabilities: [{ id: "CVE-1", cvss3_score: 3.0 }],
          ),
        }
      end

      it("exits 0 when vulns are below threshold") do
        expect { cli.run(["--gems=low_vuln_gem", "--json", "--fail-if-vulnerable=high"]) }
          .not_to(raise_error)
      end

      it("exits 1 when vulns meet threshold") do
        expect { cli.run(["--gems=low_vuln_gem", "--json", "--fail-if-vulnerable=low"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end
  end

  describe("--fail-if-outdated") do
    context("when a gem exceeds libyear threshold") do
      let(:workflow_result) do
        { "old_gem" => gem_data(last_commit_date: recent_date).merge(libyear: 4.0) }
      end

      it("exits 1") do
        expect { cli.run(["--gems=old_gem", "--json", "--fail-if-outdated=3"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    context("when all gems are within threshold") do
      let(:workflow_result) do
        { "fresh_gem" => gem_data(last_commit_date: recent_date).merge(libyear: 1.5) }
      end

      it("exits 0") do
        expect { cli.run(["--gems=fresh_gem", "--json", "--fail-if-outdated=3"]) }
          .not_to(raise_error)
      end
    end

    context("when libyear is nil") do
      let(:workflow_result) do
        { "unknown_gem" => gem_data(last_commit_date: recent_date) }
      end

      it("skips nil libyears gracefully") do
        expect { cli.run(["--gems=unknown_gem", "--json", "--fail-if-outdated=3"]) }
          .not_to(raise_error)
      end
    end
  end

  describe("--cyclonedx") do
    let(:workflow_result) { { "rack" => gem_data(last_commit_date: recent_date).merge(license: "MIT") } }

    before { allow($stdout).to(receive(:tty?).and_return(false)) }

    it("emits a CycloneDX 1.6 document to stdout when --cyclonedx=-") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--gems=rack", "--cyclonedx=-"])
      doc = JSON.parse(captured)
      expect(doc["bomFormat"]).to(eq("CycloneDX"))
      expect(doc["specVersion"]).to(eq("1.6"))
      expect(doc["components"].map { |c| c["name"] }).to(include("rack"))
    end

    it("honours --cyclonedx-version=1.7") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--gems=rack", "--cyclonedx=-", "--cyclonedx-version=1.7"])
      expect(JSON.parse(captured)["specVersion"]).to(eq("1.7"))
    end

    it("writes to a file when given a path") do
      Dir.mktmpdir do |dir|
        path = "#{dir}/sbom.json"
        cli.run(["--gems=rack", "--cyclonedx=#{path}"])
        expect(File.exist?(path)).to(be(true))
        expect(JSON.parse(File.read(path))["bomFormat"]).to(eq("CycloneDX"))
      end
    end

    it("rejects an unsupported spec version") do
      expect { cli.run(["--gems=rack", "--cyclonedx", "--cyclonedx-version=2.0"]) }
        .to(raise_error(ArgumentError, /1\.6.*1\.7/))
    end
  end

  describe("conflicting output flags") do
    before { allow($stdout).to(receive(:tty?).and_return(false)) }

    it("warns which mode wins when --sarif and --cyclonedx are combined") do
      expect do
        Dir.mktmpdir do |dir|
          File.write("#{dir}/Gemfile", "")
          File.write("#{dir}/Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (1.0)\n")
          StillActive.config.gemfile_path = "#{dir}/Gemfile"
          cli.run(["--gems=rack", "--sarif=-", "--cyclonedx=-"])
        end
      end.to(output(/multiple output modes set.*using --sarif.*ignoring --cyclonedx/m).to_stderr)
    end

    it("warns that --cyclonedx-version has no effect without --cyclonedx") do
      expect { cli.run(["--gems=rack", "--cyclonedx-version=1.7"]) }
        .to(output(/--cyclonedx-version has no effect without --cyclonedx/).to_stderr)
    end

    it("does not warn for a single output mode") do
      expect { cli.run(["--gems=rack", "--cyclonedx=-"]) }
        .not_to(output(/multiple output modes/).to_stderr)
    end
  end

  describe("Dependabot/Renovate context") do
    let(:workflow_result) { { "rack" => gem_data(last_commit_date: recent_date) } }
    let(:context) { { bot: "dependabot", bumps: [{ gem: "rack", from: "2.0.0", to: "2.0.6" }] } }

    before do
      allow($stdout).to(receive(:tty?).and_return(false))
      allow(StillActive::BotContext).to(receive(:detect).and_return(context))
    end

    it("includes pr_context in JSON output when a bot is detected") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--gems=rack", "--json"])
      parsed = JSON.parse(captured)
      expect(parsed["pr_context"]).to(include("bot" => "dependabot"))
      expect(parsed["pr_context"]["bumps"]).to(eq([{ "gem" => "rack", "from" => "2.0.0", "to" => "2.0.6" }]))
    end

    it("prepends a narrative header to markdown output") do
      lines = []
      allow($stdout).to(receive(:puts)) { |arg| lines << arg }
      cli.run(["--gems=rack", "--markdown"])
      expect(lines.first).to(include("Dependabot bump: rack 2.0.0 → 2.0.6"))
    end

    it("omits pr_context from JSON when no bot is detected") do
      allow(StillActive::BotContext).to(receive(:detect).and_return(nil))
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--gems=rack", "--json"])
      expect(JSON.parse(captured)).not_to(have_key("pr_context"))
    end
  end

  describe("--fail-if-warning") do
    context("when a gem has warning activity") do
      let(:workflow_result) { { "aging_gem" => gem_data(last_commit_date: old_date) } }

      it("exits 1") do
        expect { cli.run(["--gems=aging_gem", "--json", "--fail-if-warning"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    context("when a gem has critical activity warning") do
      let(:workflow_result) { { "stale_gem" => gem_data(last_commit_date: ancient_date) } }

      it("exits 1") do
        expect { cli.run(["--gems=stale_gem", "--json", "--fail-if-warning"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    context("when all gems are fresh") do
      let(:workflow_result) { { "fresh_gem" => gem_data(last_commit_date: recent_date) } }

      it("exits 0") do
        expect { cli.run(["--gems=fresh_gem", "--json", "--fail-if-warning"]) }
          .not_to(raise_error)
      end
    end
  end
end
