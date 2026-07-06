# frozen_string_literal: true

require_relative "../../lib/still_active/sarif/rules"
require_relative "../../lib/still_active/options"

# Cross-artifact consistency: the docs are hand-written but the source of truth
# (the SARIF rule catalog, the CLI option parser) is code. These specs derive
# the expected set from the code and assert the docs cover it, so doc-drift
# (a shipped rule nobody documented, a new flag missing from the README) fails
# the suite instead of surviving to a hand audit.
RSpec.describe("documentation consistency") do # rubocop:disable RSpec/DescribeClass -- spans two source-of-truth artifacts, not one class
  let(:root) { File.expand_path("../..", __dir__) }

  describe("SARIF rules <-> docs/rules.md") do
    let(:rule_ids) { StillActive::Sarif::Rules.all.map { |r| r[:id] } }
    let(:rules_md) { File.read(File.join(root, "docs", "rules.md")) }
    # Every `## SAxxx ...` heading in docs/rules.md is a documented rule section.
    let(:documented_ids) { rules_md.scan(/^##\s+(SA\d+)\b/).flatten }

    it("documents every rule id defined in the code catalog") do
      undocumented = rule_ids - documented_ids
      expect(undocumented).to(
        be_empty,
        "rules defined in lib/still_active/sarif/rules.rb but missing a `## <id>` section in docs/rules.md: #{undocumented.join(", ")}",
      )
    end

    it("gives each rule a lowercase anchor docs links can target") do
      # help_uri builds `docs/rules.md#saxxx`; the section headings carry `{#saxxx}`.
      rule_ids.each do |id|
        expect(rules_md).to(
          include("{##{id.downcase}}"),
          "docs/rules.md is missing the {##{id.downcase}} anchor for #{id}",
        )
      end
    end

    it("README's SA-range reference spans the full catalog (lowest to highest id)") do
      readme = File.read(File.join(root, "README.md"))
      numeric = ->(id) { id.delete_prefix("SA").to_i }
      lowest = rule_ids.min_by(&numeric)
      highest = rule_ids.max_by(&numeric)

      # e.g. "Rule reference (SA001-SA009)"; dash may be hyphen/en-dash/em-dash.
      match = readme.match(/Rule reference \((SA\d+)\s*[-–—]\s*(SA\d+)\)/)
      expect(match).not_to(
        be_nil,
        "README.md is missing the `Rule reference (SAxxx-SAyyy)` line",
      )
      expect([match[1], match[2]]).to(
        eq([lowest, highest]),
        "README SA-range reference is #{match[1]}-#{match[2]} but the code catalog spans #{lowest}-#{highest} (add the new rule to docs and update the range)",
      )
    end
  end

  describe("CLI --help <-> docs/cli.md help snapshot") do
    # The real long flags still_active emits, straight from the option parser
    # (its --help text), not a hand-maintained list.
    let(:actual_flags) do
      help = StillActive::Options.new.options_parser.to_s
      help.scan(/--[a-z][a-z0-9-]*/).uniq
    end

    # The fenced ```text block in docs/cli.md that pastes the --help output.
    # (The README links out to it rather than inlining the full reference.)
    let(:cli_help_block) do
      cli_md = File.read(File.join(root, "docs", "cli.md"))
      block = cli_md[/```text\n(.*?)\n```/m, 1]
      raise "could not find the ```text CLI options block in docs/cli.md" if block.nil?

      block
    end

    # No intentionally-hidden flags exist today: every opts.on in options.rb is
    # meant to be listed (the emoji flags have no description text but still print
    # and are documented in docs/cli.md). If a truly internal flag is ever added,
    # exclude it here with a note on why it's not user-facing.
    let(:hidden_flags) { [] }

    it("documents every long flag the CLI emits in the docs/cli.md help block") do
      expected = actual_flags - hidden_flags
      missing = expected.reject { |flag| cli_help_block.include?(flag) }
      expect(missing).to(
        be_empty,
        "flags defined in lib/still_active/options.rb but missing from the docs/cli.md help block: #{missing.join(", ")}",
      )
    end
  end
end
