# frozen_string_literal: true

require_relative "osv_client"
require_relative "helpers/endoflife_helper"

module StillActive
  # The Go toolchain, which Syft emits as the module `stdlib` (pkg:golang/stdlib@1.27.1).
  # It is a runtime, and deps.dev can't serve it: it keys versions `go1.27.1` so the
  # purl's version 404s, its index stops at go1.25.5, and its advisory list is the same
  # for every version (verified 2026-09-24). So the release lines come from
  # endoflife.date and the advisories from OSV by version, the sources the Ruby
  # runtime check already trusts.
  module GoToolchain
    extend self

    MODULE = "stdlib"

    def toolchain?(ecosystem, name)
      ecosystem == :go && name == MODULE
    end

    # Syft writes 1.27.1, a component version often go1.27.1, Trivy v1.27.1.
    def release(version)
      version.to_s.delete_prefix("go").delete_prefix("v")
    end

    # The same { info:, default:, vulnerabilities:, project_id:, version_unresolved: }
    # EcosystemLens builds from deps.dev for any other package.
    def signals(version:)
      release = release(version)
      cycles = EndoflifeHelper.fetch_cycles("/api/go.json")
      cycles = nil unless cycles.is_a?(Array) && cycles.all?(Hash) && !cycles.empty?
      latest = cycles&.first
      cycle = cycles&.find { |c| c["cycle"] == release.split(".").first(2).join(".") }
      # Only a plain release (1.20 and earlier shipped as go1.20): OSV writes Go
      # prereleases as 1.27.0-rc.1, so a `1.27rc1` query would come back empty and
      # read as clean.
      vulnerabilities = OsvClient.advisories(ecosystem: :go, name: MODULE, version: release) if release.match?(/\A\d+\.\d+(\.\d+)?\z/)
      # The status says unknown, but only JSON and CycloneDX carry it; the terminal,
      # markdown and the vulnerability gate would show zero.
      warn("warning: go/#{MODULE}@#{release} advisories not checked (not a plain release, or OSV gave no complete answer); treat it as unknown, not clean") if vulnerabilities.nil?

      {
        info: cycle && {published_at: release_date(cycle, release), licenses: [], **end_of_life(cycle, latest)},
        default: latest && {version: latest["latest"], published_at: latest["latestReleaseDate"]},
        vulnerabilities: vulnerabilities || [],
        project_id: nil,
        # No version-specific verdict: the feed is up but doesn't know this line, or
        # OSV didn't answer. Either way the status is :unknown, not a clean :ok.
        version_unresolved: (!cycles.nil? && cycle.nil?) || vulnerabilities.nil?
      }
    end

    private

    # The feed dates each line's first and latest release only.
    def release_date(cycle, release)
      if release == cycle["latest"]
        cycle["latestReleaseDate"]
      elsif [cycle["cycle"], "#{cycle["cycle"]}.0"].include?(release)
        cycle["releaseDate"]
      end
    end

    # Go supports its two newest lines. Past that the Go team has said a line gets no
    # more fixes, which is the maintainer's deprecation this field already carries.
    def end_of_life(cycle, latest)
      return {deprecated: false, deprecation_reason: nil} unless EndoflifeHelper.eol_reached?(cycle["eol"])

      # Worded as what the Go team did, since output labels it the maintainer's note.
      on = EndoflifeHelper.parse_eol(cycle["eol"])&.strftime(" on %Y-%m-%d")
      upgrade = latest && " Upgrade to #{latest["latest"]}."
      {deprecated: true, deprecation_reason: "The Go team ended the #{cycle["cycle"]} release line#{on}; it gets no further security fixes.#{upgrade}"}
    end
  end
end
