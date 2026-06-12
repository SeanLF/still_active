# frozen_string_literal: true

require "date"

RSpec.describe(StillActive::Suppressions) do
  let(:today) { Date.new(2026, 6, 12) }

  def build(entries)
    described_class.from(entries, today: today)
  end

  describe("whole-gem entries (the --ignore equivalent)") do
    it("suppresses every signal for a gem given as a bare string") do
      s = build(["legacy_gem"])
      expect(s.suppressed?(gem: "legacy_gem", signal: :activity)).to(be(true))
      expect(s.suppressed?(gem: "legacy_gem", signal: :libyear)).to(be(true))
      expect(s.suppressed?(gem: "legacy_gem", signal: :vulnerability, advisory: "CVE-2024-1")).to(be(true))
    end

    it("suppresses every signal for a gem-only hash entry") do
      s = build([{ "gem" => "legacy_gem", "reason" => "vendored" }])
      expect(s.suppressed?(gem: "legacy_gem", signal: :activity)).to(be(true))
    end

    it("does not affect other gems") do
      s = build(["legacy_gem"])
      expect(s.suppressed?(gem: "other", signal: :activity)).to(be(false))
    end
  end

  describe("signal-scoped entries") do
    it("suppresses only the named signal for the gem") do
      s = build([{ "gem" => "frozen", "signal" => "activity", "reason" => "intentionally frozen" }])
      expect(s.suppressed?(gem: "frozen", signal: :activity)).to(be(true))
      expect(s.suppressed?(gem: "frozen", signal: :libyear)).to(be(false))
      expect(s.suppressed?(gem: "frozen", signal: :vulnerability, advisory: "CVE-2024-1")).to(be(false))
    end
  end

  describe("advisory-scoped (vulnerability) entries") do
    it("suppresses the matching advisory only") do
      s = build([{ "advisory" => "CVE-2024-1234", "gem" => "nokogiri", "reason" => "no fix" }])
      expect(s.suppressed?(gem: "nokogiri", signal: :vulnerability, advisory: "CVE-2024-1234")).to(be(true))
      expect(s.suppressed?(gem: "nokogiri", signal: :vulnerability, advisory: "CVE-2024-9999")).to(be(false))
    end

    it("matches an advisory by alias, not only the primary id") do
      s = build([{ "advisory" => "CVE-2024-1234", "gem" => "nokogiri" }])
      expect(s.suppressed?(gem: "nokogiri", signal: :vulnerability, advisory: "GHSA-xxxx", aliases: ["CVE-2024-1234"])).to(be(true))
    end

    it("does not suppress the activity signal for the same gem") do
      s = build([{ "advisory" => "CVE-2024-1234", "gem" => "nokogiri" }])
      expect(s.suppressed?(gem: "nokogiri", signal: :activity)).to(be(false))
    end
  end

  describe("expiry (lapsed entries re-surface)") do
    it("applies a future-dated entry") do
      s = build([{ "gem" => "g", "signal" => "activity", "expires" => "2026-09-01" }])
      expect(s.suppressed?(gem: "g", signal: :activity)).to(be(true))
    end

    it("ignores a lapsed entry so the finding re-surfaces") do
      s = build([{ "gem" => "g", "signal" => "activity", "expires" => "2026-01-01" }])
      expect(s.suppressed?(gem: "g", signal: :activity)).to(be(false))
    end

    it("treats the expiry date itself as still valid (inclusive)") do
      s = build([{ "gem" => "g", "signal" => "activity", "expires" => "2026-06-12" }])
      expect(s.suppressed?(gem: "g", signal: :activity)).to(be(true))
    end
  end

  describe("validation warnings (invalid entries are skipped, not applied)") do
    it("rejects a vulnerability-signal entry with no advisory id, so new CVEs still surface") do
      s = build([{ "gem" => "nokogiri", "signal" => "vulnerability" }])
      expect(s.suppressed?(gem: "nokogiri", signal: :vulnerability, advisory: "CVE-2024-1")).to(be(false))
      expect(s.warnings.join).to(match(/advisory id/i))
    end

    it("rejects a signal-scoped entry with no gem") do
      s = build([{ "signal" => "activity" }])
      expect(s.warnings.join).to(match(/gem/i))
    end

    it("rejects an entry with an unknown signal") do
      s = build([{ "gem" => "g", "signal" => "nonsense" }])
      expect(s.warnings.join).to(match(/signal/i))
    end

    it("rejects an entry that is neither a gem, signal, nor advisory") do
      s = build([{ "reason" => "orphan" }])
      expect(s.warnings).not_to(be_empty)
    end

    it("does not require a reason (reason is optional)") do
      s = build([{ "gem" => "g", "signal" => "activity" }])
      expect(s.warnings).to(be_empty)
      expect(s.suppressed?(gem: "g", signal: :activity)).to(be(true))
    end
  end

  describe(".from with nil/empty input") do
    it("returns an empty suppressions set for nil") do
      expect(described_class.from(nil, today: today).suppressed?(gem: "g", signal: :activity)).to(be(false))
    end

    it("returns an empty set for an empty list") do
      expect(described_class.from([], today: today).warnings).to(be_empty)
    end
  end
end
