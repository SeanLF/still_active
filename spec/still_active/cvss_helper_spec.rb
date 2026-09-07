# frozen_string_literal: true

# Runs against the REAL cvss-suite gem, not a stub: the point is to pin the API we
# call and the numbers a known vector produces (the 9.3 reproduced in docs/rules.md).
RSpec.describe(StillActive::CvssHelper) do
  describe(".score") do
    let(:v4_base) { "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }

    it("scores a CVSS v4.0 vector at 9.3, matching FIRST.org's calculator") do
      expect(described_class.score(v4_base)).to(eq(9.3))
    end

    it("returns the BASE score, so threat metrics on the vector don't lower the number below GHSA/NVD") do
      # E:U (exploit maturity: unreported) drags cvss-suite's overall_score to 8.1; NVD
      # and GHSA publish the base score, and a gate compared against their label
      # must see the same number they do.
      expect(described_class.score("#{v4_base}/E:U")).to(eq(9.3))
    end

    it("scores a CVSS v3.1 vector at 7.5") do
      expect(described_class.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")).to(eq(7.5))
    end

    it("scores a CVSS v2 vector (no CVSS: prefix) at 7.5") do
      expect(described_class.score("AV:N/AC:L/Au:N/C:P/I:P/A:P")).to(eq(7.5))
    end

    it("returns nil for an unparseable vector") do
      expect(described_class.score("garbage")).to(be_nil)
    end

    it("returns nil for a nil or empty vector") do
      expect(described_class.score(nil)).to(be_nil)
      expect(described_class.score("")).to(be_nil)
    end

    it("returns nil, never raises, on hostile input (the number is display-only and must not crash the run)") do
      hostile = [
        "CVSS:4.0/",
        "CVSS:9.9/AV:N",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV:N/AC:L/Au:N/C:P/I:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L",
        "\u00e9" * 50,
        "x" * 20_000,
        "CVSS:4.0/#{"AV:N/" * 500}",
        12_345,
        :symbol
      ]
      hostile.each { |vector| expect(described_class.score(vector)).to(be_nil, "#{vector.to_s[0, 40].inspect} did not yield nil") }
    end
  end
end
