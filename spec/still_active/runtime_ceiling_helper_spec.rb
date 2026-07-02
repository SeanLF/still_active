# frozen_string_literal: true

require_relative "../../lib/helpers/runtime_ceiling_helper"

RSpec.describe(StillActive::RuntimeCeilingHelper) do
  # The runtime as of the fixtures: 3.3/3.4/4.0 supported, 3.2 and below EOL.
  let(:support_window) do
    {
      oldest_supported: Gem::Version.new("3.3"),
      latest_stable: Gem::Version.new("4.0.5"),
      cycles: [
        { version: Gem::Version.new("4.0"), eol: false, eol_date: Time.parse("2029-03-31") },
        { version: Gem::Version.new("3.4"), eol: false, eol_date: Time.parse("2028-03-31") },
        { version: Gem::Version.new("3.3"), eol: false, eol_date: Time.parse("2027-03-31") },
        { version: Gem::Version.new("3.2"), eol: true, eol_date: Time.parse("2026-03-31") },
        { version: Gem::Version.new("3.1"), eol: true, eol_date: Time.parse("2025-03-31") },
        { version: Gem::Version.new("3.0"), eol: true, eol_date: Time.parse("2024-04-23") },
      ],
    }
  end

  def analyze(req) = described_class.analyze(requirement: req, support_window: support_window)

  describe(".analyze") do
    context("when EOL-forced (critical): the cap admits no supported runtime") do
      it("flags a `< 3.2` cap that strands you on an EOL release, naming the ceiling and its EOL date") do
        finding = analyze("< 3.2")
        expect(finding[:eol_forced]).to(be(true))
        expect(finding[:severity]).to(eq(:critical))
        expect(finding[:ceiling_version]).to(eq("3.1")) # newest release the cap allows
        expect(finding[:ceiling_eol_date]).to(eq(Time.parse("2025-03-31")))
        expect(finding[:oldest_supported]).to(eq("3.3"))
        expect(finding[:requirement]).to(eq("< 3.2"))
      end

      it("flags a `~> 3.1.0` cap that admits only an EOL release (3.1.x)") do
        finding = analyze("~> 3.1.0")
        expect(finding[:eol_forced]).to(be(true))
        expect(finding[:severity]).to(eq(:critical))
        expect(finding[:ceiling_version]).to(eq("3.1"))
      end

      # Registries render a floor+ceiling as one comma-joined string; both bounds
      # must survive parsing or the ceiling is silently lost (real gems ship this:
      # sorbet-runtime `>= 2.3.0, < 2.7.0.preview1`, nokogiri `>= 3.2, < 4.1.dev`).
      it("flags a compound `>= 2.5, < 3.2` range, preserving the ceiling bound") do
        finding = analyze(">= 2.5, < 3.2")
        expect(finding[:eol_forced]).to(be(true))
        expect(finding[:severity]).to(eq(:critical))
        expect(finding[:ceiling_version]).to(eq("3.1"))
        expect(finding[:requirement]).to(eq(">= 2.5, < 3.2")) # receipt keeps the full string
      end
    end

    context("when latest-not-yet (note): runs on a supported runtime but not the latest stable") do
      it("flags a `~> 3.3` cap as a note with the latest stable it lacks") do
        finding = analyze("~> 3.3")
        expect(finding[:eol_forced]).to(be(false))
        expect(finding[:severity]).to(eq(:note))
        expect(finding[:latest_stable]).to(eq("4.0.5"))
      end

      it("flags a compound `>= 3.3, < 4.0` range that supports the newest 3.x but not 4.0 as a note") do
        finding = analyze(">= 3.3, < 4.0")
        expect(finding[:eol_forced]).to(be(false))
        expect(finding[:severity]).to(eq(:note))
      end

      # Grace window: the week a new Ruby ships, every gem with any upper bound
      # below it would fire a latest-not-yet note simultaneously, indicting the
      # maintainers who were honest about untested compatibility. While the latest
      # stable is still fresh, suppress the note entirely (it is about Ruby's
      # release calendar, not the gem). EOL-forced is unaffected.
      it("suppresses a latest-not-yet note while the latest stable is within its grace window") do
        window = support_window.merge(latest_stable_fresh: true)
        expect(described_class.analyze(requirement: "~> 3.3", support_window: window)).to(be_nil)
      end

      it("still flags an EOL-forced ceiling even while the latest stable is fresh (grace is note-only)") do
        window = support_window.merge(latest_stable_fresh: true)
        finding = described_class.analyze(requirement: "< 3.2", support_window: window)
        expect(finding[:eol_forced]).to(be(true))
        expect(finding[:severity]).to(eq(:critical))
      end
    end

    context("with no ceiling") do
      it("returns nil for a bare floor (`>= 3.1`, `>= 0`, empty, nil)") do
        ["", nil, ">= 0", ">= 3.1", "> 3.0"].each do |req|
          expect(analyze(req)).to(be_nil, "expected #{req.inspect} to be no ceiling")
        end
      end

      it("returns nil when the cap already admits the latest stable (`< 5.0`, `~> 4.0`)") do
        ["< 5.0", "~> 4.0"].each { |req| expect(analyze(req)).to(be_nil, "expected #{req.inspect} to be no ceiling") }
      end

      it("does NOT flag a `>= future` requires-newer floor as an EOL cap (`>= 4.1`)") do
        # Excludes every supported cycle, but by requiring a NEWER release, not by
        # capping you onto a dead one. That's a floor, not a ceiling: no finding.
        expect(analyze(">= 4.1")).to(be_nil)
        expect(analyze("~> 5.0")).to(be_nil)
      end

      it("does NOT flag a compound range whose ceiling admits the latest stable (`>= 3.2, < 4.1.dev`)") do
        # nokogiri's real shape: >= 3.2 and < 4.1 still admits Ruby 4.0. No ceiling.
        expect(analyze(">= 3.2, < 4.1.dev")).to(be_nil)
      end
    end

    context("with robustness concerns") do
      it("returns nil for an unparseable requirement rather than raising") do
        expect(analyze("not a version")).to(be_nil)
      end

      it("returns nil for a malformed clause inside an otherwise compound string, rather than raising") do
        expect { analyze(">= 2.5, <>< junk") }.not_to(raise_error)
        expect(analyze(">= 2.5, <>< junk")).to(be_nil)
      end

      it("returns nil when the support window is nil") do
        expect(described_class.analyze(requirement: "< 3.2", support_window: nil)).to(be_nil)
      end
    end

    context("when latest_stable is nil (a malformed `latest` on the feed's newest cycle)") do
      # The note needs latest_stable to compare against; the EOL-forced critical
      # needs only the cycles' eol flags. A nil latest_stable must suppress the
      # note WITHOUT hiding criticals.
      let(:support_window) { super().merge(latest_stable: nil, latest_stable_fresh: false) }

      it("still fires an EOL-forced critical (independent of latest_stable)") do
        finding = analyze("< 3.2")
        expect(finding[:eol_forced]).to(be(true))
        expect(finding[:severity]).to(eq(:critical))
      end

      it("suppresses the latest-not-yet note rather than crashing on nil") do
        expect { analyze("~> 3.3") }.not_to(raise_error)
        expect(analyze("~> 3.3")).to(be_nil)
      end
    end
  end
end
