# frozen_string_literal: true

RSpec.describe(StillActive::CvssHelper) do
  # cvss-suite is an OPTIONAL dependency (still_active doesn't declare it: it
  # over-constrains bigdecimal/bundler, which our own audit flags). These specs
  # pin the integration CONTRACT -- when the gem is present we surface its
  # overall_score, when it's absent we return nil so the OSV/GHSA label carries
  # severity -- via a stubbed CvssSuite, not the real gem, so the suite stays
  # green without bundling the flagged dependency. The golden real-vector check
  # (a v4 vector really scores 9.3, and `overall_score` is the right API) runs
  # against the actual gem in cvss_helper_real_spec.rb, via the optional-cvss CI lane.
  describe(".score") do
    let(:v4_vector) { "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }

    # The one-shot "scorer broke" warning memoizes on the module; reset it so each
    # example is hermetic regardless of order.
    before { described_class.instance_variable_set(:@warned, nil) }

    context("when cvss-suite is available") do
      before { allow(described_class).to(receive(:available?).and_return(true)) }

      it("surfaces cvss-suite's overall_score for a valid vector") do
        scored = double(valid?: true, overall_score: 9.3)
        stub_const("CvssSuite", double)
        allow(CvssSuite).to(receive(:new).with(v4_vector).and_return(scored))

        expect(described_class.score(v4_vector)).to(eq(9.3))
      end

      it("returns nil for a vector cvss-suite rejects as invalid") do
        stub_const("CvssSuite", double(new: double(valid?: false)))

        expect(described_class.score("garbage")).to(be_nil)
      end

      it("warns once and returns nil when an installed cvss-suite raises (opted-in but broken)") do
        # available? is true, so a raise means the gem loaded then failed (an
        # incompatible version, a renamed method) -- not a bad vector, which
        # cvss-suite reports via valid?. It must degrade to nil but not silently.
        stub_const("CvssSuite", double)
        allow(CvssSuite).to(receive(:new).and_raise(NoMethodError, "undefined method 'overall_score'"))

        expect { expect(described_class.score(v4_vector)).to(be_nil) }
          .to(output(/cvss-suite scoring failed: NoMethodError/).to_stderr)
        # A second failure stays silent: warn once per run, not once per advisory.
        expect { expect(described_class.score(v4_vector)).to(be_nil) }.not_to(output.to_stderr)
      end

      it("returns nil for a nil or empty vector without touching cvss-suite") do
        stub_const("CvssSuite", double)
        allow(CvssSuite).to(receive(:new))

        expect(described_class.score(nil)).to(be_nil)
        expect(described_class.score("")).to(be_nil)
        expect(CvssSuite).not_to(have_received(:new))
      end
    end

    context("when cvss-suite is not installed (optional dependency)") do
      before { allow(described_class).to(receive(:available?).and_return(false)) }

      it("returns nil even for a valid vector, so the OSV label carries severity") do
        expect(described_class.score(v4_vector)).to(be_nil)
      end
    end
  end
end
