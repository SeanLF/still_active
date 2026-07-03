# frozen_string_literal: true

RSpec.describe(StillActive::CvssHelper) do
  describe(".score") do
    it("scores a CVSS v4.0 vector -- the case deps.dev can't (it stores only 3.x)") do
      # Matches the official FIRST.org v4.0 calculator for this vector.
      expect(described_class.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).to(eq(9.3))
    end

    it("scores a CVSS v3.1 vector too") do
      expect(described_class.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")).to(eq(7.5))
    end

    it("returns nil for an invalid or absent vector (fail-safe: feeds display, must not crash the audit)") do
      expect(described_class.score("garbage")).to(be_nil)
      expect(described_class.score(nil)).to(be_nil)
      expect(described_class.score("")).to(be_nil)
    end
  end
end
