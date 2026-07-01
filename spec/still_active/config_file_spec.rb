# frozen_string_literal: true

require "tmpdir"
require "fileutils"

RSpec.describe(StillActive::ConfigFile) do
  let(:dir) { Dir.mktmpdir }

  after { FileUtils.remove_entry(dir) }

  def write(name, body)
    File.write(File.join(dir, name), body)
  end

  describe(".load") do
    it("returns an empty hash when no file is present") do
      expect(described_class.load(dir: dir)).to(eq({}))
    end

    it("parses a present .still_active.yml") do
      write(".still_active.yml", "fail_if_critical: true\n")
      expect(described_class.load(dir: dir)).to(eq("fail_if_critical" => true))
    end

    it("warns and returns an empty hash on malformed YAML") do
      write(".still_active.yml", "fail_if_critical: : :\n")
      expect { expect(described_class.load(dir: dir)).to(eq({})) }.to(output(/still_active\.yml/).to_stderr)
    end

    it("warns and returns an empty hash when the document is not a mapping") do
      write(".still_active.yml", "- just\n- a\n- list\n")
      expect { expect(described_class.load(dir: dir)).to(eq({})) }.to(output(/mapping/).to_stderr)
    end

    it("warns and returns an empty hash on a disallowed YAML class, without crashing") do
      write(".still_active.yml", "fail_if_critical: !ruby/object {}\n")
      expect { expect(described_class.load(dir: dir)).to(eq({})) }.to(output(/still_active\.yml/).to_stderr)
    end
  end

  describe(".apply") do
    let(:config) { StillActive::Config.new }

    it("maps policy flags onto the config") do
      data = {
        "fail_if_critical" => true,
        "fail_if_warning" => true,
        "fail_if_poison" => true,
        "fail_if_vulnerable" => "high",
        "fail_if_outdated" => 2.5,
        "alternatives" => true,
        "unreleased_commits" => true,
        "output" => "json",
        "safe_range_end" => 1.0,
        "warning_range_end" => 4.0,
        "parallelism" => 6,
      }
      described_class.apply(config, data, base_dir: dir)

      expect(config.fail_if_critical).to(be(true))
      expect(config.fail_if_warning).to(be(true))
      expect(config.fail_if_poison).to(be(true))
      expect(config.fail_if_vulnerable).to(eq("high"))
      expect(config.fail_if_outdated).to(eq(2.5))
      expect(config.alternatives).to(be(true))
      expect(config.unreleased_commits).to(be(true))
      expect(config.output_format).to(eq(:json))
      expect(config.no_warning_range_end).to(eq(1.0))
      expect(config.warning_range_end).to(eq(4.0))
      expect(config.parallelism).to(eq(6))
    end

    it("warns and ignores a non-boolean gate value instead of silently disabling the gate") do
      warnings = described_class.apply(config, { "fail_if_critical" => "" }, base_dir: dir)
      expect(warnings.join).to(include("fail_if_critical must be true or false"))
      expect(config.fail_if_critical).to(be(false))
    end

    it("maps direct_only so a team can commit a direct-only audit, not just pass --direct-only") do
      warnings = described_class.apply(config, { "direct_only" => true }, base_dir: dir)
      expect(config.direct_only).to(be(true))
      expect(warnings.join).not_to(include("unknown setting"))
    end

    it("warns and ignores a non-boolean direct_only instead of silently flipping scope") do
      warnings = described_class.apply(config, { "direct_only" => "yep" }, base_dir: dir)
      expect(warnings.join).to(include("direct_only must be true or false"))
      expect(config.direct_only).to(be(false))
    end

    it("treats fail_if_outdated: false as the gate being off, without crashing") do
      expect { described_class.apply(config, { "fail_if_outdated" => false }, base_dir: dir) }.not_to(raise_error)
      expect(config.fail_if_outdated).to(be_nil)
    end

    it("warns on a non-numeric threshold instead of coercing it to zero") do
      warnings = described_class.apply(config, { "safe_range_end" => "bananas" }, base_dir: dir)
      expect(warnings.join).to(include("safe_range_end must be a number"))
      expect(config.no_warning_range_end).to(eq(1.5))
    end

    it("warns on a non-positive parallelism instead of accepting it") do
      warnings = described_class.apply(config, { "parallelism" => 0 }, base_dir: dir)
      expect(warnings.join).to(include("parallelism"))
      expect(config.parallelism).to(eq(10))
    end

    it("warns and skips an import target that is valid YAML but not a mapping") do
      write("weird.yml", "- a\n- b\n")
      warnings = described_class.apply(config, { "import" => ["weird.yml"] }, base_dir: dir)
      expect(warnings.join).to(include("weird.yml"))
    end

    it("warns on an unknown top-level key") do
      warnings = described_class.apply(config, { "frobnicate" => true }, base_dir: dir)
      expect(warnings.join).to(include("frobnicate"))
    end

    it("warns on an invalid fail_if_vulnerable severity") do
      warnings = described_class.apply(config, { "fail_if_vulnerable" => "spicy" }, base_dir: dir)
      expect(warnings.join).to(match(/severity/i))
      expect(config.fail_if_vulnerable).to(be_nil)
    end

    it("builds suppressions from the ignore block") do
      data = { "ignore" => [{ "gem" => "nokogiri", "advisory" => "CVE-2024-1", "reason" => "no fix" }] }
      described_class.apply(config, data, base_dir: dir)
      expect(config.suppressions.suppressed?(gem: "nokogiri", signal: :vulnerability, advisory: "CVE-2024-1")).to(be(true))
    end

    it("imports advisory ids from a referenced .bundler-audit.yml as vulnerability suppressions") do
      write(".bundler-audit.yml", "---\nignore:\n  - CVE-2024-AUDIT\n")
      data = { "import" => [".bundler-audit.yml"] }
      described_class.apply(config, data, base_dir: dir)
      # An imported id suppresses that advisory on any gem.
      expect(config.suppressions.suppressed?(gem: "anything", signal: :vulnerability, advisory: "CVE-2024-AUDIT")).to(be(true))
      # but does not blanket-suppress other advisories
      expect(config.suppressions.suppressed?(gem: "anything", signal: :vulnerability, advisory: "CVE-OTHER")).to(be(false))
    end

    it("warns when an import target is missing") do
      warnings = described_class.apply(config, { "import" => ["nope.yml"] }, base_dir: dir)
      expect(warnings.join).to(include("nope.yml"))
    end

    it("surfaces suppression validation warnings") do
      data = { "ignore" => [{ "gem" => "x", "signal" => "vulnerability" }] }
      warnings = described_class.apply(config, data, base_dir: dir)
      expect(warnings.join).to(match(/advisory id/i))
    end
  end

  describe(".import_hint") do
    let(:config) { StillActive::Config.new }

    it("suggests importing an un-imported .bundler-audit.yml when the vuln gate is on") do
      write(".bundler-audit.yml", "---\nignore:\n  - CVE-1\n  - CVE-2\n")
      config.fail_if_vulnerable = true
      hint = described_class.import_hint({}, config: config, dir: dir)
      expect(hint).to(include(".bundler-audit.yml"))
      expect(hint).to(include("import:"))
    end

    it("stays silent when the vulnerability gate is off (suppression would not matter)") do
      write(".bundler-audit.yml", "---\nignore:\n  - CVE-1\n")
      expect(described_class.import_hint({}, config: config, dir: dir)).to(be_nil)
    end

    it("stays silent when the file is already imported") do
      write(".bundler-audit.yml", "---\nignore:\n  - CVE-1\n")
      config.fail_if_vulnerable = true
      expect(described_class.import_hint({ "import" => [".bundler-audit.yml"] }, config: config, dir: dir)).to(be_nil)
    end

    it("stays silent when there is no .bundler-audit.yml") do
      config.fail_if_vulnerable = true
      expect(described_class.import_hint({}, config: config, dir: dir)).to(be_nil)
    end

    it("stays silent when the .bundler-audit.yml has no accepted advisories") do
      write(".bundler-audit.yml", "---\nignore: []\n")
      config.fail_if_vulnerable = true
      expect(described_class.import_hint({}, config: config, dir: dir)).to(be_nil)
    end
  end
end
