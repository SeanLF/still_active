# frozen_string_literal: true

require_relative "../helpers/http_helper"

module StillActive
  # OSV (api.osv.dev) enrichment for advisories deps.dev has already discovered.
  # deps.dev is the discovery source -- it lists a package version's advisory ids --
  # but it stores only CVSS 3.x (a CVSS-4-only advisory comes back with cvss3Score
  # 0, which reads as unscored) and carries no fixed-version ranges at all. OSV
  # supplies both gaps: a GHSA severity LABEL (`database_specific.severity`) that
  # reads correctly even for a v4-only advisory, and the per-package fixed versions
  # the "capped below the fix" signal compares against a poison cap's ceiling.
  #
  # Enrichment is best-effort: any failure (missing record, transport error, odd
  # shape) leaves the advisory exactly as deps.dev produced it. It must never drop
  # an advisory the audit already found, so it only ever ADDS fields.
  module OsvClient
    extend self

    BASE_URI = URI("https://api.osv.dev/")

    # Our ecosystem symbols map to OSV's package-ecosystem casing. One advisory can
    # name the same package in several ecosystems, so we filter `affected` to the
    # one being audited. The native Bundler path carries no ecosystem and is always
    # rubygems.
    ECOSYSTEM_NAMES = { rubygems: "RubyGems", pypi: "PyPI", npm: "npm", cargo: "crates.io" }.freeze

    # Enrich each advisory in place with the OSV severity label and the fixed
    # versions for the audited package. A missing/failed lookup is a no-op on that
    # advisory (it keeps whatever deps.dev gave it), never a raise.
    def enrich(advisories, ecosystem:, name:)
      advisories.each do |advisory|
        record = detail(advisory_id: advisory[:id])
        next if record.nil?

        advisory[:osv_severity] = record[:severity_label]
        advisory[:fixed_versions] = fixed_versions(record, ecosystem: ecosystem, name: name)
      rescue StandardError => e
        # Enrichment is additive and best-effort. An unexpected OSV shape must never
        # raise out through the workflow's per-gem rescue, which would DROP the whole
        # gem and read a known-vulnerable dependency as clean. Leave the advisory
        # exactly as deps.dev produced it.
        $stderr.puts("warning: OSV enrichment for #{advisory[:id]} failed: #{e.class} (#{e.message}); leaving advisory unchanged")
      end
    end

    # Fetch and parse one OSV record by advisory id (GHSA/CVE). Returns
    # { severity_label:, affected: [{ ecosystem:, name:, fixed: [...] }] } or nil
    # when the id is absent or OSV has no usable record for it. A non-object body
    # (a CDN/error envelope that parses to an array or scalar) yields nil rather
    # than raising on `dig`.
    def detail(advisory_id:)
      return if advisory_id.nil?

      body = HttpHelper.get_json(BASE_URI, "/v1/vulns/#{encode(advisory_id)}")
      return unless body.is_a?(Hash)

      {
        severity_label: body.dig("database_specific", "severity"),
        affected: Array(body["affected"]).filter_map { |entry| parse_affected(entry) },
      }
    end

    private

    # The fixed versions declared for `name` in `ecosystem` across the record's
    # affected packages (a branch-structured advisory carries one fix per maintained
    # line, so several can apply). Empty when the package is enumerated by
    # `versions` with no fix boundary, or isn't present in this ecosystem. When the
    # ecosystem symbol has no OSV mapping (an ecosystem we don't audit for fixes),
    # match by name alone rather than silently dropping every fix.
    def fixed_versions(record, ecosystem:, name:)
      osv_ecosystem = ECOSYSTEM_NAMES.fetch(ecosystem || :rubygems, nil)
      record[:affected]
        .select { |a| a[:name] == name && (osv_ecosystem.nil? || a[:ecosystem] == osv_ecosystem) }
        .flat_map { |a| a[:fixed] }
        .uniq
    end

    # Shape guards throughout: a malformed entry (null/scalar where an object is
    # expected, or an object where an array is) is skipped, not raised on, so one
    # bad `affected`/`ranges`/`events` element can't discard the good fixed versions
    # beside it in the same record.
    def parse_affected(entry)
      return unless entry.is_a?(Hash)

      package = entry["package"]
      return unless package.is_a?(Hash) && package["name"]

      fixed = Array(entry["ranges"]).flat_map do |range|
        next [] unless range.is_a?(Hash)

        Array(range["events"]).filter_map { |event| event["fixed"] if event.is_a?(Hash) }
      end
      { ecosystem: package["ecosystem"], name: package["name"], fixed: fixed }
    end

    def encode(value)
      URI.encode_www_form_component(value.to_s)
    end
  end
end
