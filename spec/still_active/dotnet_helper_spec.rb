# frozen_string_literal: true

require_relative "../../lib/still_active/helpers/dotnet_helper"

RSpec.describe(StillActive::DotnetHelper) do
  describe(".classify") do
    it("maps a .NET 5+ moniker to the dotnet runtime, major-only cycle") do
      expect(described_class.classify("net6.0")).to(eq({family: :dotnet, version: Gem::Version.new("6")}))
      expect(described_class.classify("net10.0")).to(eq({family: :dotnet, version: Gem::Version.new("10")}))
    end

    it("maps a netcoreapp moniker to the dotnet runtime, keeping the minor") do
      expect(described_class.classify("netcoreapp3.1")).to(eq({family: :dotnet, version: Gem::Version.new("3.1")}))
      expect(described_class.classify("netcoreapp2.1")).to(eq({family: :dotnet, version: Gem::Version.new("2.1")}))
    end

    it("maps a .NET Framework moniker (no dot) to dotnetfx, expanding the digits") do
      expect(described_class.classify("net48")).to(eq({family: :dotnetfx, version: Gem::Version.new("4.8")}))
      expect(described_class.classify("net461")).to(eq({family: :dotnetfx, version: Gem::Version.new("4.6.1")}))
      expect(described_class.classify("net45")).to(eq({family: :dotnetfx, version: Gem::Version.new("4.5")}))
    end

    it("excludes netstandard (a compatibility contract, not a runtime)") do
      expect(described_class.classify("netstandard2.0")).to(be_nil)
      expect(described_class.classify("netstandard1.3")).to(be_nil)
    end

    it("strips a platform suffix before classifying") do
      expect(described_class.classify("net6.0-windows")).to(eq({family: :dotnet, version: Gem::Version.new("6")}))
      expect(described_class.classify("net7.0-android")).to(eq({family: :dotnet, version: Gem::Version.new("7")}))
    end

    it("tolerates the long-form and case variants deps.dev also emits") do
      expect(described_class.classify(".NETFramework4.7.2")).to(eq({family: :dotnetfx, version: Gem::Version.new("4.7.2")}))
      expect(described_class.classify(".NETStandard2.0")).to(be_nil)
      expect(described_class.classify(".NETCoreApp3.1")).to(eq({family: :dotnet, version: Gem::Version.new("3.1")}))
    end

    it("returns nil for an unrecognized moniker rather than guessing") do
      expect(described_class.classify("")).to(be_nil)
      expect(described_class.classify("portable-net45")).to(be_nil)
      expect(described_class.classify(nil)).to(be_nil)
    end
  end

  describe(".analyze") do
    # A minimal support window shaped like EndoflifeHelper.support_window: only
    # the cycles list is read by analyze.
    def window(cycles)
      {cycles: cycles.map { |v, eol, date| {version: Gem::Version.new(v), eol: eol, eol_date: date && Time.parse(date)} }}
    end

    let(:dotnet) do
      window([["10", false, nil], ["9", false, nil], ["8", false, nil], ["6", true, "2024-11-12"], ["5", true, "2022-05-10"], ["3.1", true, "2022-12-13"]])
    end
    let(:dotnetfx) do
      # endoflife's dotnetfx feed keys .NET Framework 3.5 as "3.5-sp1" (the only
      # non-numeric cycle), still supported to 2029 via Windows servicing.
      window([["4.8", false, nil], ["4.5", true, "2016-01-12"], ["3.5-sp1", false, "2029-01-09"]])
    end

    it("fires when every concrete runtime target is EOL, pointing at the newest-EOL as the ceiling") do
      finding = described_class.analyze(target_frameworks: ["net5.0", "netcoreapp3.1"], dotnet: dotnet, dotnetfx: dotnetfx)
      expect(finding).to(include(eol_forced: true, severity: :critical, runtime: ".NET"))
      # net5.0 (EOL 2022-05) vs netcoreapp3.1 (EOL 2022-12): 3.1 outlived 5, so the
      # longest-lived dead runtime -- the best the package offers -- is the ceiling.
      expect(finding[:ceiling_version]).to(eq("3.1"))
      expect(finding[:ceiling_eol_date]).to(eq(Time.parse("2022-12-13")))
    end

    it("does NOT fire when a netstandard target offers a supported path, even if every concrete runtime is EOL") do
      # THE honesty rule: netstandard2.0 is consumable from a current .NET, so an
      # otherwise-EOL package (Newtonsoft.Json 13.0.3 targets net6.0 + net45 +
      # netstandard2.0) is not capped. Without this, the signal fires on nearly
      # every modern .NET library.
      expect(described_class.analyze(target_frameworks: ["net5.0", "net45", "netstandard2.0"], dotnet: dotnet, dotnetfx: dotnetfx)).to(be_nil)
    end

    it("does not fire when at least one concrete runtime target is still supported") do
      expect(described_class.analyze(target_frameworks: ["net5.0", "net8.0"], dotnet: dotnet, dotnetfx: dotnetfx)).to(be_nil)
    end

    it("does not fire for a netstandard-only package (no concrete runtime target)") do
      expect(described_class.analyze(target_frameworks: ["netstandard2.0", "netstandard2.1"], dotnet: dotnet, dotnetfx: dotnetfx)).to(be_nil)
    end

    it("fires across families when both an EOL .NET Framework and an EOL .NET are the only targets") do
      finding = described_class.analyze(target_frameworks: ["net45", "net5.0"], dotnet: dotnet, dotnetfx: dotnetfx)
      expect(finding).to(include(eol_forced: true))
      # net5.0 EOL 2022-05 outlives net45 EOL 2016 -> .NET 5 is the ceiling.
      expect(finding).to(include(runtime: ".NET", ceiling_version: "5"))
    end

    it("matches a Framework cycle keyed with a service-pack suffix (net35 -> 3.5-sp1)") do
      # net35 maps to "3.5"; the feed keys it "3.5-sp1". Matched by release segment,
      # net35 is a still-supported target -- an escape hatch -- so a package targeting
      # net35 + the EOL net45 is NOT capped. Without release-matching it read as an
      # unknown cycle and the set false-fired critical.
      expect(described_class.analyze(target_frameworks: ["net35", "net45"], dotnet: dotnet, dotnetfx: dotnetfx)).to(be_nil)
    end

    it("returns nil when the support window is unavailable (feed down)") do
      expect(described_class.analyze(target_frameworks: ["net5.0"], dotnet: nil, dotnetfx: nil)).to(be_nil)
    end

    it("ignores a target whose cycle isn't in the feed rather than guessing its EOL") do
      # net20 (2.0) predates dotnetfx's floor; treat as unknown, not a fabricated EOL.
      # With only an unknown target and nothing else, there's no concrete-EOL basis to fire.
      expect(described_class.analyze(target_frameworks: ["net20"], dotnet: dotnet, dotnetfx: dotnetfx)).to(be_nil)
    end
  end
end
