# frozen_string_literal: true

require_relative "../../../lib/still_active/sarif/rules"

RSpec.describe(StillActive::Sarif::Rules) do
  describe(".all") do
    subject(:rules) { described_class.all }

    it("returns the SA001..SA010 catalog") do
      expect(rules.map { |r| r[:id] }).to(eq(["SA001", "SA002", "SA003", "SA004", "SA005", "SA006", "SA007", "SA008", "SA009", "SA010"]))
    end

    it("every rule has required fields") do
      expect(rules).to(all(include(:id, :name, :short, :full, :help_text, :help_markdown, :level, :tags)))
    end

    it("every rule has a stable level (error/warning/note)") do
      expect(rules.map { |r| r[:level] }.uniq - ["error", "warning", "note"]).to(be_empty)
    end

    it("security rules carry numeric security-severity and a CWE tag") do
      ["SA001", "SA003", "SA006", "SA007"].each do |id|
        rule = rules.find { |r| r[:id] == id }
        expect(rule[:security_severity]).to(match(/\A\d+\.\d+\z/), "#{id} missing security-severity")
        expect(rule[:tags].any? { |t| t.start_with?("external/cwe/cwe-") })
          .to(be(true), "#{id} missing CWE tag")
      end
    end

    it("non-security rules omit security-severity") do
      ["SA002", "SA004", "SA005"].each do |id|
        rule = rules.find { |r| r[:id] == id }
        expect(rule[:security_severity]).to(be_nil, "#{id} should not have security-severity")
      end
    end

    it("rules are frozen (immutable catalog)") do
      expect(rules.first).to(be_frozen)
    end

    it("help_markdown contains a link to the rule's docs anchor") do
      rules.each do |r|
        expect(r[:help_markdown]).to(include("##{r[:id].downcase}"), "#{r[:id]} markdown missing anchor link")
      end
    end
  end

  describe(".all(:neutral)") do
    subject(:rules) { described_class.all(:neutral) }

    # The rule catalog is emitted once per SARIF run (tool.driver.rules[]), and a
    # cross-ecosystem SBOM run can be polyglot, so the wording can't be per-result.
    # The neutral flavour is the fallback the SBOM path uses so a Go/npm/pypi repo's
    # Code Scanning alerts don't read as "Gem ...". The native Ruby path keeps `gem`.
    it("drops the native-only SA006 (Ruby EOL) the SBOM path can never emit") do
      # A Go/npm repo's Code Scanning tab should not advertise a "Ruby runtime EOL"
      # rule. Every other stable id survives, in order.
      expect(rules.map { |r| r[:id] }).to(eq(["SA001", "SA002", "SA003", "SA004", "SA005", "SA007", "SA008", "SA009", "SA010"]))
    end

    it("carries no gem/RubyGems/Gemfile wording anywhere in the neutral catalog") do
      # SA009 legitimately names Ruby as ONE of several runtime-ceiling examples
      # (alongside Python and .NET), so a bare "ruby" is fine; the leak we guard is
      # Ruby-package-manager framing that implies a Ruby audit.
      rules.each do |r|
        text = [r[:short], r[:full], r[:help_text]].join(" ")
        expect(text).not_to(match(/\bgems?\b/i), "#{r[:id]} still mentions a gem: #{text.inspect}")
        expect(text).not_to(match(/rubygems|gemfile|bundle update/i), "#{r[:id]} still names a Ruby-only artefact: #{text.inspect}")
      end
    end

    it("drops the Ruby-specific `bundle update` advice from SA004") do
      expect(rules.find { |r| r[:id] == "SA004" }[:help_text]).not_to(include("bundle"))
    end

    it("rebuilds help_markdown from the neutral help_text (still links the docs anchor)") do
      sa004 = rules.find { |r| r[:id] == "SA004" }
      expect(sa004[:help_markdown]).to(start_with(sa004[:help_text]))
      expect(sa004[:help_markdown]).to(include("#sa004"))
    end
  end

  describe(".all default flavour") do
    it("keeps the native Ruby `gem` idiom (unchanged for the Gemfile path)") do
      expect(described_class.all.find { |r| r[:id] == "SA002" }[:short])
        .to(eq("Gem has had no release for over 3 years"))
    end
  end

  describe(".find") do
    it("looks up by id") do
      expect(described_class.find("SA001")[:name]).to(eq("ArchivedRepository"))
    end

    it("returns nil for unknown id") do
      expect(described_class.find("SA999")).to(be_nil)
    end
  end

  describe(".help_uri") do
    it("builds a docs URL with anchor") do
      expect(described_class.help_uri("SA002")).to(end_with("/docs/rules.md#sa002"))
    end
  end

  describe(".severity_to_level") do
    {
      "critical" => "error",
      "high" => "error",
      "medium" => "warning",
      "low" => "note",
      # An unscored advisory (no CVSS score and no OSV label) fails closed to warning,
      # never an informational note -- the SARIF analogue of the CLI fail-closed gate.
      nil => "warning"
    }.each do |label, expected|
      it("maps #{label.inspect} -> #{expected}") do
        expect(described_class.severity_to_level(label)).to(eq(expected))
      end
    end
  end

  describe(".cvss_to_security_severity") do
    it("formats a CVSS score as a one-decimal string") do
      expect(described_class.cvss_to_security_severity(9.1)).to(eq("9.1"))
      expect(described_class.cvss_to_security_severity(5.0)).to(eq("5.0"))
    end

    it("returns nil for nil input") do
      expect(described_class.cvss_to_security_severity(nil)).to(be_nil)
    end
  end
end
