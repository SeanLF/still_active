# frozen_string_literal: true

# Golden check against the REAL cvss-suite gem (the optional dependency), not a
# stub. It pins two things the stubbed cvss_helper_spec can't: that we call the
# right API (`overall_score`, not `base_score`) and that a known vector still
# scores the number reproduced in docs/rules.md and the commit history. cvss-suite
# is absent from the default bundle, so these skip there; the `optional-cvss` CI
# lane (Gemfile.cvss) installs the gem and runs them, and so does any dev who has
# it. Tagged :real_cvss so that lane can target them.
RSpec.describe(StillActive::CvssHelper, :real_cvss) do
  before { skip("cvss-suite not installed") unless described_class.available? }

  describe(".score against the installed cvss-suite") do
    it("scores a CVSS v4.0 vector at 9.3, matching FIRST.org's calculator") do
      expect(described_class.score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).to(eq(9.3))
    end

    it("scores a CVSS v3.1 vector at 7.5") do
      expect(described_class.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")).to(eq(7.5))
    end

    it("returns nil for an unparseable vector") do
      expect(described_class.score("garbage")).to(be_nil)
    end
  end
end
