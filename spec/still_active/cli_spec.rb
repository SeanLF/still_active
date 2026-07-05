# frozen_string_literal: true

require "tempfile"
require "tmpdir"

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

    it("exposes the computed activity_level verdict per gem, so machine consumers need not recompute it") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--gems=rails", "--json"])
      payload = JSON.parse(captured)
      # rails has a recent commit and no releases here, so it lands :ok.
      expect(payload.dig("gems", "rails", "activity_level")).to(eq("ok"))
    end

    it("serializes date fields as ISO8601 UTC strings matching generated_at, not Ruby's default Time#to_s") do
      # Production passes real Time objects (with whatever offset the upstream
      # API carried) into the JSON; a bare Time#to_json emits "2026-01-02
      # 01:04:05 +0200", a different format and timezone from generated_at.
      tz_time = Time.new(2026, 1, 2, 3, 4, 5, "+02:00")
      result = { "rails" => gem_data(last_commit_date: tz_time).merge(latest_version_release_date: tz_time) }
      allow(StillActive::Workflow).to(receive_messages(
        call: result,
        ruby_freshness: { version: "3.4.0", eol: false, release_date: tz_time },
      ))
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--gems=rails", "--json"])
      payload = JSON.parse(captured)

      iso_utc = /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/
      expect(payload.dig("gems", "rails", "last_commit_date")).to(match(iso_utc))
      # +02:00 03:04:05 normalizes to UTC 01:04:05.
      expect(payload.dig("gems", "rails", "latest_version_release_date")).to(eq("2026-01-02T01:04:05Z"))
      expect(payload.dig("ruby", "release_date")).to(eq("2026-01-02T01:04:05Z"))
    end

    # #128 shipped a schema that rejected any real --json output carrying a
    # vulnerability: OSV enrichment adds keys the strict `additionalProperties:
    # false` schema didn't list, and the old contract test passed only because its
    # fixture was minimal. The guard against that class of drift is a fixture that
    # is EXHAUSTIVE -- it must exercise every field the emitters can produce, so
    # validating it makes any emitted-but-unschema'd key fail. The tests below both
    # validate that exhaustive output and prove the fixture is actually exhaustive
    # (schema property <=> emitted key, in both directions).
    describe("published JSON Schema conformance (exhaustive)") do
      require "json_schemer"

      # Plain methods (not `let`) to stay under RSpec/MultipleMemoizedHelpers; the
      # file reads are cheap and run a handful of times.
      def schema_path = File.expand_path("../../docs/still_active.schema.json", __dir__)
      def schema_md_path = File.expand_path("../../docs/schema.md", __dir__)
      def schema = JSON.parse(File.read(schema_path))

      # Ruby freshness carrying every `ruby` schema field.
      def exhaustive_ruby
        {
          version: "3.4.0",
          release_date: Time.new(2025, 1, 1, 0, 0, 0, "+00:00"),
          eol_date: Time.new(2028, 1, 1, 0, 0, 0, "+00:00"),
          eol: false,
          latest_version: "3.4.1",
          latest_release_date: Time.new(2026, 1, 1, 0, 0, 0, "+00:00"),
          libyear: 0.1,
        }
      end

      # A bot context carrying every `pr_context` field (bot, bumps, and a bump's
      # gem/from/to).
      def exhaustive_pr_context
        { bot: "dependabot", bumps: [{ gem: "rack", from: "2.0.0", to: "2.0.6" }] }
      end

      # A result that exercises EVERY per-gem / vulnerability / constraint /
      # language_ceiling field the schema defines, spread across four gems. Values
      # are real Time objects where the emitters produce them (the JSON layer
      # normalizes those to ISO8601 UTC strings). Field provenance is cross-checked
      # against the code that emits each key: workflow.rb (scorecard_maintained),
      # osv_client.rb (osv_severity/osv_cvss_score/cvss_version/cvss_vector/
      # fixed_versions), vulnerability_helper.rb (no_fix_available via merge),
      # poison_security_correlator.rb (poison_security_relevant/poison_below_fix and
      # the constraint below-fix keys) and ceiling_reconciler.rb (upgrade_blocked).
      def exhaustive_result
        {
          "rails" => {
            source_type: :rubygems,
            direct: true,
            version_used: "7.0.0",
            latest_version: "7.1.0",
            latest_version_release_date: Time.new(2026, 1, 1, 0, 0, 0, "+00:00"),
            latest_pre_release_version: "7.2.0.beta1",
            latest_pre_release_version_release_date: Time.new(2026, 2, 1, 0, 0, 0, "+00:00"),
            repository_url: "https://github.com/rails/rails",
            last_commit_date: recent_date,
            archived: false,
            scorecard_score: 8.5,
            # deps.dev's Maintained sub-check, attached alongside scorecard_score;
            # absent from the pre-#128 fixture, so the schema's own field went
            # unvalidated by real output.
            scorecard_maintained: 7.0,
            vulnerability_count: 0,
            vulnerabilities: [],
            ruby_gems_url: "https://rubygems.org/gems/rails",
            up_to_date: false,
            version_used_release_date: Time.new(2025, 1, 1, 0, 0, 0, "+00:00"),
            version_yanked: false,
            license: "MIT",
            libyear: 1.2,
            unreleased_commits: 17,
          },
          "rack" => {
            source_type: :rubygems,
            direct: false,
            dependency_path: ["rails", "actionpack", "rack"],
            last_commit_date: recent_date,
            # up_to_date as null (unknown), the other half of its boolean|null type;
            # rails covers the boolean half.
            up_to_date: nil,
            vulnerability_count: 1,
            alternatives: ["foo"],
            # A fully OSV-enriched advisory: every vulnerability key the emitters can
            # attach (deps.dev's cvss3/cvss2/source, OSV's osv_severity/osv_cvss_score/
            # cvss_version/cvss_vector/fixed_versions, ruby-advisory-db's
            # no_fix_available). osv_cvss_score is a real number here (the null half is
            # implicit for un-enriched advisories) so both branches of its type hold.
            vulnerabilities: [{ id: "CVE-2024-1", url: "https://example/x", title: "t", aliases: ["GHSA-x"], cvss3_score: 7.5, cvss3_vector: "AV:N", cvss2_score: nil, source: "merged", osv_severity: "MODERATE", osv_cvss_score: 8.1, cvss_version: "3.0", cvss_vector: "CVSS:3.0/AV:N/AC:L", fixed_versions: ["2.0.6", "1.6.11"], no_fix_available: false }],
          },
          # A poison-pill gem: every constraint field including the security below-
          # the-fix keys the correlator sets.
          "protected_attributes" => {
            source_type: :rubygems,
            direct: true,
            poison: true,
            poison_severity: :critical,
            poison_security_relevant: true,
            poison_below_fix: true,
            constraints: [{ dependency: "activemodel", requirement: "< 5.0", dep_latest: "8.0.1", majors_behind: 4, kind: :ceiling, capped_dep_vulnerable: true, capped_below_fix: true, below_fix_advisory: "CVE-2024-9", below_fix_fixed_in: "5.0.0" }],
          },
          # A language-ceiling gem: every language_ceiling field, including
          # upgrade_blocked (set by CeilingReconciler when a poison cap blocks the
          # very upgrade that would lift the ceiling), which fixed_by_upgrade flips to
          # false alongside.
          "cfpropertylist" => {
            source_type: :rubygems,
            direct: true,
            version_used: "3.0.9",
            latest_version: "4.0.0",
            language_ceiling: {
              runtime: "Ruby",
              requirement: "< 3.2",
              eol_forced: true,
              severity: :critical,
              ceiling_version: "3.1",
              ceiling_eol_date: Time.new(2025, 3, 31, 0, 0, 0, "+00:00"),
              oldest_supported: "3.3",
              latest_stable: "4.0.5",
              fixed_by_upgrade: false,
              upgrade_blocked: true,
            },
          },
        }
      end

      def emit_payload(result: exhaustive_result, ruby_info: exhaustive_ruby, pr_context: exhaustive_pr_context)
        allow(StillActive::Workflow).to(receive_messages(call: result, ruby_freshness: ruby_info))
        allow(StillActive::BotContext).to(receive(:detect).and_return(pr_context))
        captured = nil
        allow($stdout).to(receive(:puts)) { |arg| captured = arg }
        cli.run(["--gems=rails", "--json"])
        JSON.parse(captured)
      end

      it("emits JSON that validates against the published JSON Schema and carries a summary digest") do
        payload = emit_payload
        errors = JSONSchemer.schema(Pathname.new(schema_path)).validate(payload).to_a
        expect(errors).to(be_empty, errors.map { |e| "#{e["data_pointer"]}: #{e["type"]} (#{e["data"].inspect})" }.join("\n"))
        expect(payload["summary"]).to(include("total_gems" => 4, "direct" => 3, "transitive" => 1, "vulnerable_gems" => 1, "ruby_eol" => false))
      end

      # Proves the fixture above is genuinely exhaustive: every property the schema
      # defines is actually present in the emitted output. Without this, a new
      # emitted field could be added to both code and schema while the fixture never
      # exercises it -- and an unschema'd sibling of that field would then slip past
      # additionalProperties:false unnoticed, exactly the #128 hole. When this fails,
      # add the named field to exhaustive_result so real output guards it.
      it("exercises every field the schema defines (so additionalProperties:false actually guards each one)") do
        payload = emit_payload
        gems = payload.fetch("gems").values
        emitted = {
          "gem" => gems.flat_map(&:keys),
          "vulnerability" => gems.flat_map { |g| g["vulnerabilities"] || [] }.flat_map(&:keys),
          "constraint" => gems.flat_map { |g| g["constraints"] || [] }.flat_map(&:keys),
          "language_ceiling" => gems.filter_map { |g| g["language_ceiling"] }.flat_map(&:keys),
          "ruby" => payload.fetch("ruby").keys,
          "summary" => payload.fetch("summary").keys,
          "pr_context" => payload.fetch("pr_context").keys,
        }
        emitted.each do |defn, keys|
          missing = schema.dig("$defs", defn, "properties").keys - keys.uniq
          expect(missing).to(be_empty, "the exhaustive fixture never exercises #{defn} field(s): #{missing.join(", ")} -- add them so additionalProperties:false is actually tested against real emitted output")
        end
        top_missing = schema.fetch("properties").keys - payload.keys
        expect(top_missing).to(be_empty, "the exhaustive fixture never exercises top-level field(s): #{top_missing.join(", ")}")
      end

      # The direct #128 regression: a key the emitters produce but the schema does
      # not list must fail validation, not pass silently. Injecting a bogus key into
      # the exhaustive (otherwise-valid) output confirms additionalProperties:false
      # bites -- if this ever passes, the schema has stopped catching emitted drift.
      it("rejects a gem carrying a key the schema does not list") do
        poisoned = exhaustive_result
        poisoned["rails"] = poisoned["rails"].merge(bogus_unschema_key: "x")
        payload = emit_payload(result: poisoned)
        errors = JSONSchemer.schema(Pathname.new(schema_path)).validate(payload).to_a
        offending = errors.find { |e| e["data_pointer"] == "/gems/rails/bogus_unschema_key" }
        expect(offending).not_to(be_nil, "additionalProperties:false did not reject an unschema'd gem key; errors: #{errors.map { |e| e["data_pointer"] }.inspect}")
        expect(offending["schema_pointer"]).to(include("additionalProperties"))
      end

      # schema.json and schema.md drifted apart before #128. Keep them in step: every
      # field schema.json defines for these object types must be documented in the
      # prose table. Scoped to the object types schema.md documents field-by-field.
      # LIMITATIONS: (1) language_ceiling is excluded -- schema.md documents it as a
      # single "See SA009" row, not per sub-field, so its keys (ceiling_version,
      # upgrade_blocked, ...) are a known, accepted doc gap rather than drift. (2) The
      # reverse direction (every backticked token in schema.md maps to a schema
      # property) isn't asserted: schema.md backticks example values, flags and
      # literals too, so exact matching there is too noisy to be reliable.
      it("documents every schema.json field in schema.md (they drifted before #128)") do
        md = File.read(schema_md_path)
        ["gem", "vulnerability", "constraint", "ruby", "summary"].each do |defn|
          schema.dig("$defs", defn, "properties").each_key do |prop|
            expect(md).to(match(/\b#{Regexp.escape(prop)}\b/), "schema.json defines #{defn}.#{prop} but schema.md never documents it")
          end
        end
      end
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

  describe("granular suppressions") do
    def suppress(entries)
      StillActive.config.suppressions = StillActive::Suppressions.from(entries)
    end

    def vuln_gem(ids)
      gem_data(last_commit_date: recent_date).merge(
        vulnerability_count: ids.size,
        vulnerabilities: ids.map { |id| { id: id, aliases: [] } },
      )
    end

    it("does not exit when the only critical gem has its activity signal suppressed") do
      StillActive.config.fail_if_critical = true
      suppress([{ "gem" => "stale_gem", "signal" => "activity", "reason" => "vendored, frozen" }])
      expect { cli.send(:check_exit_status, { "stale_gem" => gem_data(last_commit_date: ancient_date) }) }
        .not_to(raise_error)
    end

    it("still exits when an activity suppression targets a different gem") do
      StillActive.config.fail_if_critical = true
      suppress([{ "gem" => "other", "signal" => "activity" }])
      expect { cli.send(:check_exit_status, { "stale_gem" => gem_data(last_commit_date: ancient_date) }) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("suppresses one advisory but still fails on a different unaccepted one") do
      StillActive.config.fail_if_vulnerable = true
      suppress([{ "gem" => "vuln_gem", "advisory" => "CVE-1", "reason" => "no fix" }])
      expect { cli.send(:check_exit_status, { "vuln_gem" => vuln_gem(["CVE-1", "CVE-2"]) }) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("does not exit when every advisory on the gem is suppressed") do
      StillActive.config.fail_if_vulnerable = true
      suppress([{ "gem" => "vuln_gem", "advisory" => "CVE-1" }, { "gem" => "vuln_gem", "advisory" => "CVE-2" }])
      expect { cli.send(:check_exit_status, { "vuln_gem" => vuln_gem(["CVE-1", "CVE-2"]) }) }
        .not_to(raise_error)
    end

    it("does not let an advisory suppression hide the same gem going critical") do
      StillActive.config.fail_if_critical = true
      suppress([{ "gem" => "g", "advisory" => "CVE-1" }])
      expect { cli.send(:check_exit_status, { "g" => gem_data(last_commit_date: ancient_date) }) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("re-surfaces (exits 1) once a suppression has lapsed") do
      StillActive.config.fail_if_critical = true
      suppress([{ "gem" => "stale_gem", "signal" => "activity", "expires" => "2000-01-01" }])
      expect { cli.send(:check_exit_status, { "stale_gem" => gem_data(last_commit_date: ancient_date) }) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
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

    context("with a confirmed advisory of unknown (unscored) severity") do
      let(:workflow_result) do
        {
          "fresh_cve_gem" => gem_data(last_commit_date: recent_date).merge(
            vulnerability_count: 1,
            vulnerabilities: [{ id: "CVE-fresh", cvss3_score: nil, cvss2_score: nil }],
          ),
        }
      end

      it("fails a =high gate closed rather than silently passing an unscored advisory, and says why on stderr") do
        allow($stdout).to(receive(:puts))
        expect { cli.run(["--gems=fresh_cve_gem", "--json", "--fail-if-vulnerable=high"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) }
            .and(output(/fresh_cve_gem has an advisory of unknown severity \(CVE-fresh\)/).to_stderr))
      end

      it("still lets a granular suppression accept the specific advisory (fail-closed has an escape hatch)") do
        Dir.mktmpdir do |dir|
          Dir.chdir(dir) do
            File.write(".still_active.yml", "ignore:\n  - gem: fresh_cve_gem\n    advisory: CVE-fresh\n")
            allow($stdout).to(receive(:puts))
            allow($stderr).to(receive(:puts))
            expect { cli.run(["--gems=fresh_cve_gem", "--json", "--fail-if-vulnerable=high"]) }.not_to(raise_error)
          end
        end
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

    it("exits 2 with a friendly error on an unsupported spec version (not a backtrace)") do
      allow($stderr).to(receive(:puts))
      expect { cli.run(["--gems=rack", "--cyclonedx", "--cyclonedx-version=2.0"]) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) })
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

  describe("--markdown alternatives") do
    let(:workflow_result) do
      { "paperclip" => gem_data(last_commit_date: ancient_date).merge(archived: true, alternatives: ["shrine", "carrierwave"]) }
    end

    it("appends an Alternatives section to markdown output") do
      lines = []
      allow($stdout).to(receive(:puts)) { |arg| lines << arg }
      cli.run(["--gems=paperclip", "--markdown"])
      output = lines.join("\n")
      expect(output).to(include("**Alternatives**"))
      expect(output).to(include("`paperclip`: shrine, carrierwave"))
    end
  end

  describe("--markdown poison-pill") do
    let(:workflow_result) do
      {
        "protected_attributes" => gem_data(last_commit_date: ancient_date).merge(
          poison: true,
          constraints: [{ dependency: "activemodel", requirement: "< 5.0", dep_latest: "8.0.1", majors_behind: 4, kind: :ceiling }],
        ),
      }
    end

    it("appends a Poison-pill findings section to markdown output") do
      lines = []
      allow($stdout).to(receive(:puts)) { |arg| lines << arg }
      cli.run(["--gems=protected_attributes", "--markdown"])
      output = lines.join("\n")
      expect(output).to(include("**Poison-pill findings**"))
      expect(output).to(include("`protected_attributes` caps `activemodel` `< 5.0` (4 majors behind, latest 8.x)"))
    end
  end

  describe("--fail-if-poison") do
    def poison_gem(severity = :critical)
      gem_data(last_commit_date: ancient_date).merge(
        poison: true,
        poison_severity: severity,
        constraints: [{ dependency: "activemodel", requirement: "< 5.0", dep_latest: "8.0.1", majors_behind: 4, kind: :ceiling }],
      )
    end

    it("exits 1 when a critical poison-pill meets the default (warning) threshold") do
      StillActive.config.fail_if_poison = true
      expect { cli.send(:check_exit_status, { "protected_attributes" => poison_gem(:critical) }) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("does NOT exit on a note-level poison-pill under the default (warning) threshold") do
      StillActive.config.fail_if_poison = true
      expect { cli.send(:check_exit_status, { "tty-reader" => poison_gem(:note) }) }.not_to(raise_error)
    end

    it("exits on a note-level pill when the threshold is lowered to note") do
      StillActive.config.fail_if_poison = :note
      expect { cli.send(:check_exit_status, { "tty-reader" => poison_gem(:note) }) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("does not exit when no gem is a poison-pill") do
      StillActive.config.fail_if_poison = true
      expect { cli.send(:check_exit_status, { "rails" => gem_data(last_commit_date: recent_date) }) }
        .not_to(raise_error)
    end

    it("does not exit when the flag is off, even with a poison gem") do
      expect { cli.send(:check_exit_status, { "protected_attributes" => poison_gem }) }
        .not_to(raise_error)
    end

    it("does not exit when the poison gem is --ignore'd") do
      StillActive.config.fail_if_poison = true
      StillActive.config.ignored_gems = ["protected_attributes"]
      expect { cli.send(:check_exit_status, { "protected_attributes" => poison_gem }) }
        .not_to(raise_error)
    end

    it("does not exit when the gem's poison signal is suppressed in .still_active.yml") do
      StillActive.config.fail_if_poison = true
      StillActive.config.suppressions = StillActive::Suppressions.from(
        [{ "gem" => "protected_attributes", "signal" => "poison", "reason" => "vendored, accepted" }],
      )
      expect { cli.send(:check_exit_status, { "protected_attributes" => poison_gem }) }
        .not_to(raise_error)
    end
  end

  describe("--fail-if-language-ceiling") do
    def ceiling_gem(severity = :critical)
      gem_data(last_commit_date: recent_date).merge(
        language_ceiling: { requirement: "< 3.2", eol_forced: severity == :critical, severity: severity },
      )
    end

    # Ceiling findings only ever carry :critical (EOL-forced) or :note
    # (latest-not-yet) -- there is no :warning tier -- so the bare gate defaults to
    # :critical (the real blocker), not the :warning poison uses.
    it("exits 1 when an EOL-forcing (critical) ceiling meets the default (critical) threshold") do
      StillActive.config.fail_if_language_ceiling = true
      expect { cli.send(:check_exit_status, { "cfpropertylist" => ceiling_gem(:critical) }) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("does NOT exit on a note-level ceiling under the default (critical) threshold") do
      StillActive.config.fail_if_language_ceiling = true
      expect { cli.send(:check_exit_status, { "somegem" => ceiling_gem(:note) }) }.not_to(raise_error)
    end

    it("exits on a note-level ceiling when the threshold is lowered to note") do
      StillActive.config.fail_if_language_ceiling = :note
      expect { cli.send(:check_exit_status, { "somegem" => ceiling_gem(:note) }) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("does not exit when the flag is off, even with a ceiling gem") do
      expect { cli.send(:check_exit_status, { "cfpropertylist" => ceiling_gem }) }.not_to(raise_error)
    end

    it("does not exit when the gem's language_ceiling signal is suppressed in .still_active.yml") do
      StillActive.config.fail_if_language_ceiling = true
      StillActive.config.suppressions = StillActive::Suppressions.from(
        [{ "gem" => "cfpropertylist", "signal" => "language_ceiling", "reason" => "pinned on purpose" }],
      )
      expect { cli.send(:check_exit_status, { "cfpropertylist" => ceiling_gem }) }.not_to(raise_error)
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

  # The 2.0 headline is layered config (CLI flag > env > .still_active.yml >
  # default). The apply/load units are tested in isolation; this exercises the
  # ordering through CLI#run with a real file on disk, the contract a user sees.
  describe("config precedence") do
    let(:workflow_result) { { "rails" => gem_data(last_commit_date: recent_date) } }

    around do |example|
      Dir.mktmpdir { |dir| Dir.chdir(dir) { example.run } }
    end

    it("lets a CLI flag override a conflicting .still_active.yml value") do
      File.write(".still_active.yml", "safe_range_end: 5\n")
      cli.run(["--gems=rails", "--json", "--safe-range-end=2"])
      expect(StillActive.config.no_warning_range_end).to(eq(2.0))
    end

    it("applies a .still_active.yml value when no CLI flag overrides it") do
      File.write(".still_active.yml", "safe_range_end: 5\n")
      cli.run(["--gems=rails", "--json"])
      expect(StillActive.config.no_warning_range_end).to(eq(5.0))
    end

    it("falls back to the default when neither the file nor a flag sets it") do
      cli.run(["--gems=rails", "--json"])
      expect(StillActive.config.no_warning_range_end).to(eq(1.5))
    end
  end

  describe("stale suppression warnings") do
    let(:workflow_result) { { "rails" => gem_data(last_commit_date: recent_date) } }

    around do |example|
      Dir.mktmpdir { |dir| Dir.chdir(dir) { example.run } }
    end

    it("warns when a .still_active.yml suppression names a gem not in the audit") do
      File.write(".still_active.yml", "ignore:\n  - gem: ghost_gem\n    signal: activity\n")
      expect { cli.run(["--gems=rails", "--json"]) }.to(output(/ghost_gem/).to_stderr)
    end
  end

  describe("SBOM audit (--sbom)") do
    # A CycloneDX doc with one assessable dep (pypi) and one the reader refuses
    # to silently drop (an unmapped ecosystem). The real reader runs; only the
    # network fan-out (SbomWorkflow) is stubbed.
    let(:sbom_body) do
      {
        components: [
          { type: "library", name: "flask", purl: "pkg:pypi/flask@2.0.0" },
          { type: "library", name: "Alamofire", purl: "pkg:cocoapods/Alamofire@5.0.0" },
        ],
      }.to_json
    end

    def lens_data(vulnerable: false)
      {
        ecosystem: :pypi,
        name: "flask",
        version_used: "2.0.0",
        latest_version_release_date: recent_date,
        last_commit_date: recent_date,
        archived: false,
        vulnerability_count: vulnerable ? 1 : 0,
        vulnerabilities: vulnerable ? [{ id: "CVE-2026-0001", severity: "high" }] : [],
      }
    end

    def outcome(assessed, failures: [])
      StillActive::SbomWorkflow::Outcome.new(assessed: assessed, failures: failures)
    end

    # The around chdir's into a tmpdir, so tests reference the SBOM by this bare
    # relative path without threading an instance variable through.
    around do |example|
      Dir.mktmpdir do |dir|
        Dir.chdir(dir) do
          File.write("sbom.json", sbom_body)
          example.run
        end
      end
    end

    before do
      allow($stdout).to(receive(:tty?).and_return(false))
      allow($stderr).to(receive(:tty?).and_return(false))
      allow(StillActive::SbomWorkflow).to(receive(:call).and_return(outcome({ "pypi/flask@2.0.0" => lens_data })))
      # deps.dev vuln-schema canary runs once per SBOM audit; keep it green by
      # default so unrelated cases stay network-free. The degraded case is its own test.
      allow(StillActive::DepsDevClient).to(receive(:advisory_schema_ok?).and_return(true))
    end

    it("warns loudly (does not present an authoritative all-clear) when the deps.dev vuln schema canary fails") do
      allow(StillActive::DepsDevClient).to(receive(:advisory_schema_ok?).and_return(false))
      allow($stdout).to(receive(:puts))
      expect { cli.run(["--sbom=sbom.json"]) }
        .to(output(/deps\.dev vulnerability schema check failed.*not authoritative/im).to_stderr)
    end

    it("dispatches on --sbom without a Gemfile, emitting an SBOM-shaped JSON report") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--sbom=sbom.json"])
      payload = JSON.parse(captured)
      expect(payload).to(include("schema_version" => 1))
      # A different shape from the Ruby audit: no $schema contract, no `gems` block.
      expect(payload).not_to(include("$schema"))
      expect(payload).not_to(include("gems"))
      expect(payload.dig("tool", "name")).to(eq("still_active"))
      # Keyed "ecosystem/name@version" so same-name packages can't collide.
      expect(payload.dig("dependencies", "pypi/flask@2.0.0", "status")).to(eq("ok"))
      expect(payload.dig("dependencies", "pypi/flask@2.0.0", "activity_level")).to(eq("ok"))
    end

    it("surfaces a dependency's production flag in the JSON when the SBOM marked it") do
      allow(StillActive::SbomWorkflow).to(receive(:call)
        .and_return(outcome({ "pypi/flask@2.0.0" => lens_data.merge(production: false) })))
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--sbom=sbom.json"])
      # A dev/test-only dep stays labelled through serialization, so a consumer can
      # separate prod risk from test debt (false must survive as false, not vanish).
      expect(JSON.parse(captured).dig("dependencies", "pypi/flask@2.0.0", "production")).to(be(false))
    end

    it("omits the production key when the SBOM left prod/dev unknown") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--sbom=sbom.json"])
      # The default lens_data carries no production key (syft-style unknown); the
      # JSON must not invent one, so unknown stays unknown rather than a false all-clear.
      expect(JSON.parse(captured).dig("dependencies", "pypi/flask@2.0.0")).not_to(have_key("production"))
    end

    it("summarizes assessed vs unassessable and the worst status") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      cli.run(["--sbom=sbom.json"])
      summary = JSON.parse(captured).fetch("summary")
      expect(summary).to(include("total_assessed" => 1, "unassessable_count" => 1, "status" => "ok"))
      expect(summary.dig("status_counts", "ok")).to(eq(1))
    end

    it("surfaces the deps it could not assess in the JSON and warns on stderr, never silently dropping them") do
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      expect { cli.run(["--sbom=sbom.json"]) }.to(output(/1 dependency could not be assessed/).to_stderr)
      unassessable = JSON.parse(captured).fetch("unassessable")
      expect(unassessable).to(contain_exactly(
        include("name" => "Alamofire", "ecosystem" => "cocoapods", "reason" => "unsupported_ecosystem"),
      ))
    end

    it("applies the vulnerability gate to lens data, exiting 1 on a vulnerable dependency") do
      allow(StillActive::SbomWorkflow).to(receive(:call).and_return(outcome({ "pypi/flask@2.0.0" => lens_data(vulnerable: true) })))
      allow($stdout).to(receive(:puts))
      expect { cli.run(["--sbom=sbom.json", "--fail-if-vulnerable"]) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("fails a =high severity gate closed on an unscored advisory, same as the native path") do
      # The cross-ecosystem lens emits a minimal advisory (no CVSS) when detail
      # fetch fails; a severity gate must not silently pass it.
      vuln = lens_data.merge(vulnerability_count: 1, vulnerabilities: [{ id: "CVE-unscored", cvss3_score: nil, cvss2_score: nil }])
      allow(StillActive::SbomWorkflow).to(receive(:call).and_return(outcome({ "pypi/flask@2.0.0" => vuln })))
      allow($stdout).to(receive(:puts))
      allow($stderr).to(receive(:puts))
      expect { cli.run(["--sbom=sbom.json", "--fail-if-vulnerable=high"]) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
    end

    it("surfaces an assessment-time failure (a raised lens call) in the JSON and the stderr count, never silently dropping it") do
      # A rate-limited/flaky deps.dev raises mid-assess; the dep must still reach
      # the report, or a transient hiccup shrinks the audit scope invisibly.
      failure = { ecosystem: :pypi, name: "flask", version: "2.0.0", reason: :assessment_error, error: "Net::ReadTimeout: timed out" }
      allow(StillActive::SbomWorkflow).to(receive(:call).and_return(outcome({}, failures: [failure])))
      captured = nil
      allow($stdout).to(receive(:puts)) { |arg| captured = arg }
      # 1 reader-level (cocoapods) + 1 assessment failure = 2 unassessable.
      expect { cli.run(["--sbom=sbom.json"]) }.to(output(/2 dependencies could not be assessed/).to_stderr)
      payload = JSON.parse(captured)
      expect(payload.dig("summary", "total_assessed")).to(eq(0))
      expect(payload.dig("summary", "unassessable_count")).to(eq(2))
      expect(payload.fetch("unassessable")).to(include(
        include("name" => "flask", "reason" => "assessment_error", "error" => /ReadTimeout/),
      ))
    end

    it("exits 2 with a friendly error when combining --sbom with --gems (not a backtrace)") do
      allow($stderr).to(receive(:puts))
      expect { cli.run(["--sbom=sbom.json", "--gems=rails"]) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) })
    end

    it("exits 2 with a friendly error when the SBOM file does not exist (not a backtrace)") do
      expect { cli.run(["--sbom=/no/such/sbom.json"]) }
        .to(output(/error: SBOM file not found/).to_stderr.and(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) }))
    end

    it("exits 2 on a present-but-unparseable SBOM instead of reporting a silent empty audit") do
      File.write("broken.json", "{ this is not json")
      allow($stderr).to(receive(:puts))
      expect { cli.run(["--sbom=broken.json"]) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) })
    end

    it("exits 2 when the SBOM is valid JSON but not CycloneDX (no components array)") do
      File.write("wrong.json", '{"spdxVersion":"SPDX-2.3","packages":[]}')
      allow($stderr).to(receive(:puts))
      expect { cli.run(["--sbom=wrong.json"]) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) })
    end

    it("exits 2 (not a stacktrace) when the --sbom path exists but can't be read as a file") do
      Dir.mkdir("a_directory")
      allow($stderr).to(receive(:puts))
      # A directory passes Options' File.exist? check but File.read raises EISDIR.
      expect { cli.run(["--sbom=a_directory"]) }
        .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(2)) })
    end
  end
end
