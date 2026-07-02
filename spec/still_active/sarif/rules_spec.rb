# frozen_string_literal: true

require_relative "../../../lib/still_active/sarif/rules"

RSpec.describe(StillActive::Sarif::Rules) do
  describe(".all") do
    subject(:rules) { described_class.all }

    it("returns the SA001..SA009 catalog") do
      expect(rules.map { |r| r[:id] }).to(eq(["SA001", "SA002", "SA003", "SA004", "SA005", "SA006", "SA007", "SA008", "SA009"]))
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

  describe(".cvss_to_level") do
    {
      9.5 => "error",
      7.0 => "error",
      6.9 => "warning",
      5.0 => "warning",
      4.0 => "warning",
      3.9 => "note",
      0.1 => "note",
      nil => "note",
    }.each do |score, expected|
      it("maps #{score.inspect} -> #{expected}") do
        expect(described_class.cvss_to_level(score)).to(eq(expected))
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
