# frozen_string_literal: true

require_relative "constraint_helper"
require_relative "endoflife_helper"

module StillActive
  # The NuGet calibration layer for the language-runtime ceiling (SA009), the
  # .NET sibling of RubyHelper/PythonHelper. NuGet is shaped differently from
  # Ruby/Python: a package declares not one version RANGE but a SET of target
  # framework monikers (net6.0, netcoreapp3.1, net48, netstandard2.0). Targeting a
  # framework is an enforced restore-time wall (NuGet error NU1202), so if EVERY
  # concrete runtime the package targets is end-of-life, consuming it forces your
  # project onto a dead runtime -- the same "no supported runtime is reachable"
  # cap the Ruby/Python ceiling catches, expressed as a set rather than a range.
  #
  # The honesty rule is the netstandard exclusion: `netstandard*` is a
  # compatibility contract consumable FROM a modern .NET, not a runtime, so it
  # imposes no ceiling. Without excluding it the signal would fire on nearly every
  # modern library. We therefore fire only when the package has at least one
  # concrete runtime target AND every concrete runtime target is EOL.
  module DotnetHelper
    extend self

    # The two .NET runtime calendars, fetched once per SBOM. .NET Core/5+ is a
    # single unified endoflife feed; .NET Framework 4.x is its own (`dotnetfx`),
    # with a different EOL schedule tied to Windows servicing.
    def supported_dotnet_range = EndoflifeHelper.support_window(feed_path: "/api/dotnet.json")
    def supported_dotnetfx_range = EndoflifeHelper.support_window(feed_path: "/api/dotnetfx.json")

    # A target framework moniker -> { family: :dotnet | :dotnetfx, version: } (the
    # runtime it names and the endoflife.date cycle to look it up by), or nil when
    # the moniker is not a concrete runtime (netstandard, or unrecognized -- we
    # never guess). Tolerates deps.dev's short form (net45, netcoreapp3.1), its
    # long form (.NETFramework4.5), platform suffixes (net6.0-windows), and case.
    def classify(moniker)
      return if moniker.nil?

      m = moniker.to_s.strip.downcase
      return if m.empty?

      # Drop a platform suffix (net6.0-windows -> net6.0) and the long-form dot.
      dash = m.index("-")
      m = m[0, dash] if dash
      m = m.delete_prefix(".")

      return if m.start_with?("netstandard") # a compatibility contract, not a runtime

      # Ordered, mutually-exclusive prefixes; the load-bearing distinction is the
      # dot: a dotted "netX.Y" is .NET 5+ (major cycle), a dot-less "netXY" is .NET
      # Framework (digits expand to the cycle).
      if m.start_with?("netcoreapp")
        dotnet(m.delete_prefix("netcoreapp")) # netcoreapp3.1 -> .NET "3.1" (minor kept)
      elsif m.start_with?("netframework")
        dotnetfx(m.delete_prefix("netframework"))    # long form: .NETFramework4.7.2
      elsif m.start_with?("net")
        rest = m.delete_prefix("net")
        if rest.include?(".")
          dotnet(rest.split(".").first)              # net6.0 -> .NET "6" (major only)
        elsif all_digits?(rest)
          dotnetfx(expand_framework_digits(rest))    # net48 -> .NET Framework "4.8"
        end
      end
    end

    # Whether a moniker is a netstandard target (tolerating the long-form ".NETStandard"
    # and platform/case variants) -- the escape hatch analyze must honour.
    def netstandard?(moniker)
      return false if moniker.nil?

      moniker.to_s.strip.downcase.delete_prefix(".").start_with?("netstandard")
    end

    # => the SA009 eol_forced finding hash, or nil when the package is not capped.
    # `dotnet` / `dotnetfx` are EndoflifeHelper.support_window results (or nil when
    # the feed is down); only their :cycles list is read.
    def analyze(target_frameworks:, dotnet:, dotnetfx:)
      monikers = Array(target_frameworks)
      # THE honesty rule: a netstandard target is a compatibility contract
      # consumable from a current .NET, so its mere presence is an escape hatch --
      # the package is not capped, whatever else it targets. Without this the signal
      # fires on nearly every modern .NET library (Newtonsoft.Json, EF Core, ...),
      # which all ship a netstandard2.0 target alongside older concrete runtimes.
      return if monikers.any? { |moniker| netstandard?(moniker) }

      runtimes = monikers.filter_map do |moniker|
        classification = classify(moniker)
        classification&.merge(moniker: moniker, cycle: cycle_for(classification, dotnet: dotnet, dotnetfx: dotnetfx))
      end
      return if runtimes.empty?

      # A still-supported runtime target is a clear escape hatch: not capped.
      return if runtimes.any? { |r| r[:cycle] && r[:cycle][:eol] == false }

      eol = runtimes.select { |r| r[:cycle] && r[:cycle][:eol] == true }
      return if eol.empty? # nothing KNOWN-EOL: don't fabricate a ceiling from unknown cycles

      # The longest-lived dead runtime is the best the package offers -- the ceiling.
      ceiling = eol.max_by { |r| r[:cycle][:eol_date] || Time.at(0) }
      finding = {
        requirement: runtimes.map { |r| r[:moniker] }.uniq.sort.join(", "),
        eol_forced: true,
        runtime: (ceiling[:family] == :dotnetfx) ? ".NET Framework" : ".NET",
        ceiling_version: ceiling[:version].to_s,
        ceiling_eol_date: ceiling[:cycle][:eol_date]
      }
      finding.merge(severity: ConstraintHelper.constraint_severity(finding))
    end

    private

    # "461" -> "4.6.1", "48" -> "4.8", "45" -> "4.5": first digit is the major, each
    # remaining digit a further segment. Only called on an all-digit remainder.
    def expand_framework_digits(digits) = ([digits[0]] + digits[1..].chars).join(".")

    def all_digits?(str)
      !str.empty? && str.chars.all? { |c| ("0".."9").cover?(c) }
    end

    def dotnet(version) = build(:dotnet, version)
    def dotnetfx(version) = build(:dotnetfx, version)

    def build(family, version)
      return unless version && Gem::Version.correct?(version)

      {family: family, version: Gem::Version.new(version)}
    end

    # The endoflife cycle for a classified target, or nil when the feed is down or
    # the cycle isn't tracked (an ancient net20 predating the feed) -- unknown, not
    # assumed EOL.
    def cycle_for(classification, dotnet:, dotnetfx:)
      window = (classification[:family] == :dotnetfx) ? dotnetfx : dotnet
      return if window.nil?

      # Match on the release segment, ignoring any prerelease suffix: endoflife
      # keys .NET Framework 3.5 as "3.5-sp1", so net35 ("3.5") must still match it
      # (otherwise a still-supported target reads as unknown and can false-fire).
      target = classification[:version].release
      window[:cycles].find { |cycle| cycle[:version].release == target }
    end
  end
end
