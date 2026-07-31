# frozen_string_literal: true

require_relative "../helpers/http_helper"
require_relative "../helpers/cvss_helper"

module StillActive
  # OSV (api.osv.dev) enrichment for advisories deps.dev has already discovered.
  # deps.dev is the discovery source -- it lists a package version's advisory ids --
  # but it stores only CVSS 3.x (a CVSS-4-only advisory comes back with cvss3Score
  # 0, which reads as unscored) and carries no fixed-version ranges at all. OSV
  # supplies all three gaps: a GHSA severity LABEL (`database_specific.severity`)
  # that reads correctly even for a v4-only advisory, the CVSS v4 VECTOR (turned into
  # a real score, so the finding carries a security-severity number), and the
  # per-package fixed versions the "capped below the fix" signal compares against a
  # poison cap's ceiling.
  #
  # Enrichment is best-effort: any failure (missing record, transport error, odd
  # shape) leaves the advisory exactly as deps.dev produced it.
  #
  # OSV is also the ARBITER of whether a deps.dev-discovered advisory really applies
  # to the audited version (see reject_unaffected), which is the one place this module
  # removes rather than adds. That direction is the dangerous one -- a wrongly dropped
  # advisory reads a vulnerable dependency as clean -- so every degrade path here must
  # resolve to "keep", and only an unambiguous OSV contradiction may drop.
  module OsvClient
    extend self

    BASE_URI = URI("https://api.osv.dev/")

    # Every ecosystem SbomReader/deps.dev resolve, mapped to OSV's package-ecosystem
    # casing (verified against live OSV records). One advisory can name the same
    # package in several ecosystems, so `affected` is filtered to the one being
    # audited; the native Bundler path carries no ecosystem and is always rubygems.
    # Anything unmapped falls back to name-only fix filtering rather than dropping fixes.
    ECOSYSTEM_NAMES = {
      rubygems: "RubyGems",
      pypi: "PyPI",
      npm: "npm",
      cargo: "crates.io",
      maven: "Maven",
      go: "Go",
      nuget: "NuGet"
    }.freeze

    # Prefer the newest CVSS version a record carries (v4 is the whole point: it's the
    # one deps.dev can't score). `severity[].score` is the vector STRING, oddly named.
    CVSS_PRIORITY = {"CVSS_V4" => 3, "CVSS_V3" => 2, "CVSS_V2" => 1}.freeze
    # A v2 vector has no `CVSS:X.Y` prefix, so the version can't be read from the
    # string; fall back to the entry type so the CycloneDX rating method labels it v2.
    TYPE_VERSIONS = {"CVSS_V4" => "4.0", "CVSS_V3" => "3.1", "CVSS_V2" => "2.0"}.freeze

    # Enrich each advisory in place with the OSV severity label and the fixed
    # versions for the audited package, and return the advisories that survive
    # version confirmation (see reject_unaffected). A missing/failed lookup is a
    # no-op on that advisory (it keeps whatever deps.dev gave it), never a raise.
    def enrich(advisories, ecosystem:, name:, version: nil)
      # Each eligible advisory is paired with OSV's own identifiers for it, which the
      # confirmation match needs alongside deps.dev's (see detail).
      backed = advisories.filter_map do |advisory|
        osv_ids = apply_record(advisory, ecosystem: ecosystem, name: name)
        [advisory, osv_ids] if osv_ids
      end
      reject_unaffected(advisories, backed, ecosystem: ecosystem, name: name, version: version)
    rescue => e
      # The confirmation pass runs outside apply_record's per-advisory rescue, and an
      # escape from here would hit the workflow's per-gem rescue and strip the gem of
      # ALL its signals -- reading a known-vulnerable dependency as clean, the very
      # thing this module exists to prevent. Keep every advisory instead.
      warn("warning: OSV version confirmation for #{name} failed: #{e.class} (#{e.message}); keeping every advisory")
      advisories
    end

    # Fetch and parse one OSV record by advisory id (GHSA/CVE). Returns
    # { severity_label:, cvss_score:, cvss_version:, cvss_vector:, affected: [...] }
    # or nil when the id is absent or OSV has no usable record for it. A non-object
    # body (a CDN/error envelope that parses to an array or scalar) yields nil rather
    # than raising on `dig`.
    def detail(advisory_id:)
      return if advisory_id.nil?

      body = HttpHelper.get_json(BASE_URI, "/v1/vulns/#{encode(advisory_id)}")
      return unless body.is_a?(Hash)

      cvss = best_cvss(body)
      {
        # OSV's own identity for the advisory, unioned into the match against a query
        # result. Asking for a CVE returns the GHSA record (OSV resolves aliases), so
        # deps.dev's id alone can miss the id the query answers with, and reading a
        # listed advisory as absent would drop a real finding.
        identifiers: [body["id"], *Array(body["aliases"])].grep(String),
        severity_label: body.dig("database_specific", "severity"),
        cvss_score: cvss[:score],
        cvss_version: cvss[:version],
        cvss_vector: cvss[:vector],
        affected: Array(body["affected"]).filter_map { |entry| parse_affected(entry) }
      }
    end

    private

    # Applies one OSV record to one advisory, in place. Returns OSV's identifiers for
    # the advisory when it is eligible for the version confirmation below (only OSV
    # data may overrule OSV-derived data), or nil when it is not and must be kept
    # whatever the query says.
    def apply_record(advisory, ecosystem:, name:)
      record = detail(advisory_id: advisory[:id])
      return if record.nil?

      advisory[:osv_severity] = record[:severity_label]
      advisory[:osv_cvss_score] = record[:cvss_score]
      advisory[:cvss_version] = record[:cvss_version]
      advisory[:cvss_vector] = record[:cvss_vector]
      advisory[:fixed_versions] = fixed_versions(record, ecosystem: ecosystem, name: name)
      record[:identifiers] if names_package?(record, ecosystem: ecosystem, name: name)
    rescue => e
      # Enrichment is additive and best-effort. An unexpected OSV shape must never
      # raise out through the workflow's per-gem rescue, which would DROP the whole
      # gem and read a known-vulnerable dependency as clean. Leave the advisory
      # exactly as deps.dev produced it, and hold it (nil) rather than risk
      # dropping it on a record we couldn't read.
      warn("warning: OSV enrichment for #{advisory[:id]} failed: #{e.class} (#{e.message}); leaving advisory unchanged")
      nil
    end

    # Drops the advisories that OSV's own version matching says don't apply to the
    # audited version. deps.dev is the discovery source, but it MIRRORS OSV/GHSA data
    # with an ingestion lag, and advisories get AMENDED after publication: the usual
    # shape is a CVE published with a fix on the current release line, then backports
    # to the older supported lines, then an amendment adding those branch ranges. Until
    # deps.dev re-ingests, it keeps serving the pre-amendment record, whose broader
    # range still covers versions the amendment has since marked patched.
    #
    # Receipt (2026-07-31): GHSA-mh99-v99m-4gvg was published 07-24 with a single
    # range, introduced 0 / fixed 5.0.8. Backports 3.0.3, 2.1.3 and 1.1.17 shipped
    # 07-27 to 07-29, and the advisory was amended 07-31 19:39Z to carry all four
    # branches. Hours later deps.dev still answered from the 07-24 record, reporting
    # the patched 1.1.17/1.1.18/2.1.3/2.1.4/3.0.3 as vulnerable.
    #
    # This is lag, NOT a parsing defect: 391 advisories across rubygems/pypi/cargo and
    # 29 multi-branch npm SEMVER advisories were checked against OSV and every one
    # agreed. So the correction has to be a live re-check, not a local range fix. We
    # ask OSV's /v1/query, deps.dev's own upstream, which applies the declared ranges
    # under each ecosystem's semantics and reflects an amendment immediately. It also
    # saves reimplementing cross-ecosystem version ordering.
    #
    # The window reopens with every backported fix, so this is structural, not a
    # one-off worth waiting out.
    #
    # Removing a finding is the one direction this tool must never get wrong, so a drop
    # needs positive contradiction on every count: the advisory came from deps.dev ALONE
    # (ruby-advisory-db does its own version matching and is the Ruby authority, so its
    # verdict stands), OSV served a record for it that names this package under this
    # ecosystem and spelling, and the query for this exact version succeeded without
    # listing it. Anything unknown -- no version, unmapped ecosystem, failed query --
    # keeps the advisory.
    def reject_unaffected(advisories, backed, ecosystem:, name:, version:)
      candidates = backed.select { |advisory, _osv_ids| advisory[:source] == "deps.dev" }
      return advisories if candidates.empty? || version.to_s.empty?

      affected = affected_identifiers(ecosystem: ecosystem, name: name, version: version)
      return advisories if affected.nil?

      unaffected = candidates
        .reject { |advisory, osv_ids| (identifiers(advisory) | osv_ids).intersect?(affected) }
        .map(&:first)
      advisories - unaffected
    end

    # Every advisory identifier OSV reports as affecting this exact package version,
    # or nil when the question can't be asked or answered (unmapped ecosystem, failed
    # request, unusable body). An EMPTY array is a real answer -- "nothing affects this
    # version" -- and must stay distinct from the nil, which means "we don't know".
    #
    # That distinction is the whole safety of the drop, so an empty array is only ever
    # returned for a body that positively IS an empty OSV result. OSV's genuine all-clear
    # is a bare `{}` (verified live, and identical to what an unknown package name
    # returns), which gives a malformed or truncated body no distinguishing marker of
    # its own: read loosely, every unparseable 200 would fabricate an all-clear.
    def affected_identifiers(ecosystem:, name:, version:)
      osv_ecosystem = ECOSYSTEM_NAMES[ecosystem || :rubygems]
      return if osv_ecosystem.nil?

      query = {version: version, package: {name: name, ecosystem: osv_ecosystem}}
      body = HttpHelper.post_json(BASE_URI, "/v1/query", body: JSON.generate(query))
      return unless body.is_a?(Hash)

      identifiers_from(body)
    rescue => e
      warn("warning: OSV version confirmation for #{name}@#{version} failed: #{e.class} (#{e.message}); keeping every advisory")
      nil
    end

    # The identifiers in one /v1/query body, or nil when the body isn't a complete,
    # readable answer. A truncated answer is not an answer: OSV paginates past 1000
    # vulnerabilities OR once a query exceeds 20 seconds, and documents that a page can
    # carry ONLY a next_page_token. That second trigger is latency, not package size, so
    # it can land on any package on a slow day; reading it as "nothing affects this
    # version" would drop real findings at random. We decline to filter rather than
    # walk the pages, since the pass only ever removes false positives.
    def identifiers_from(body)
      return if body["next_page_token"] || body["nextPageToken"]
      # A bare `{}` is OSV's genuine "nothing affects this version" (verified live). It
      # has to be matched exactly, not as "no vulns key": an error envelope served with a
      # 200 (`{"code":3,"message":...}`) has no vulns key either, and reading that as an
      # all-clear would drop every advisory on the package.
      return [] if body.empty?

      vulns = body["vulns"]
      return unless vulns.is_a?(Array)
      # EVERY entry has to be readable, not just one of them. Skipping the unreadable
      # ones would silently shorten the list, and a short list is indistinguishable from
      # OSV not listing that advisory at all: the one it named but we couldn't parse
      # would be dropped as unaffected. `all?` holds on an empty array, so OSV's other
      # genuine all-clear shape, `{"vulns": []}`, still answers.
      return unless vulns.all? { |vuln| vuln.is_a?(Hash) && vuln["id"].is_a?(String) }

      vulns.flat_map { |vuln| [vuln["id"], *vuln["aliases"]] }.grep(String)
    end

    # An advisory's own id plus its aliases, mirroring VulnerabilityHelper's merge
    # identity: OSV keys a record by GHSA while deps.dev may hand us the CVE (or the
    # reverse), so matching on the primary id alone would read a listed advisory as
    # absent and drop a real finding.
    def identifiers(advisory)
      [advisory[:id], *advisory[:aliases]].compact.map(&:to_s)
    end

    # Does this record carry version data for the audited package, under the exact
    # ecosystem and spelling we're querying with? Both halves guard a fabricated
    # all-clear, because OSV answers an unknown package and a patched version with the
    # same bare `{}`:
    #
    # NAME -- registry name normalization differs by ecosystem (PyPI folds case and
    # -/_/.), so a spelling mismatch would turn a missed lookup into "not affected".
    # Exact equality is stricter than OSV's own matching, which costs us the fix on a
    # case-divergent name; that's the safe direction to be wrong in.
    #
    # VERSIONED -- an affected entry with no ranges and no version list (or one whose
    # window lives somewhere /v1/query can't match on, like a GIT range) is OSV having
    # no opinion on versions at all. The query can then never return that record for
    # ANY version, so treating its silence as contradiction would drop the advisory
    # permanently, for every user, while deps.dev still asserts the version is affected.
    def names_package?(record, ecosystem:, name:)
      osv_ecosystem = ECOSYSTEM_NAMES[ecosystem || :rubygems]
      record[:affected].any? { |a| a[:name] == name && a[:ecosystem] == osv_ecosystem && a[:versioned] }
    end

    # The highest-version CVSS vector the record carries, as { score:, version:,
    # vector: } (a computed base score, the "3.1"/"4.0" version, and the raw string),
    # or all-nil. deps.dev has no v4 score, so this is what gives a CVSS-4-only
    # advisory a real number for the security-severity/rating.
    def best_cvss(body)
      entry = Array(body["severity"])
        .select { |s| s.is_a?(Hash) && CVSS_PRIORITY.key?(s["type"]) }
        .max_by { |s| CVSS_PRIORITY[s["type"]] }
      return {} if entry.nil?

      vector = entry["score"]
      {score: CvssHelper.score(vector), version: cvss_version(vector) || TYPE_VERSIONS[entry["type"]], vector: vector}
    end

    # The X.Y version from a "CVSS:X.Y/..." vector prefix, or nil.
    def cvss_version(vector)
      vector.to_s[%r{\ACVSS:(\d+\.\d+)/}, 1]
    end

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

      ranges = Array(entry["ranges"]).select { |range| range.is_a?(Hash) }
      fixed = ranges.flat_map { |range| Array(range["events"]).filter_map { |event| event["fixed"] if event.is_a?(Hash) } }
      {ecosystem: package["ecosystem"], name: package["name"], fixed: fixed, versioned: version_matchable?(entry, ranges)}
    end

    # Range types /v1/query can resolve a VERSION against. A GIT range is commit-graph
    # data a version query never matches, so a record carrying only those has no version
    # opinion to contradict deps.dev with. A range missing its type reads the same way.
    VERSION_RANGE_TYPES = ["SEMVER", "ECOSYSTEM"].freeze

    # Does this affected entry hold data a version query could match on -- an explicit
    # version list, or a version-ordered range? See names_package? for why the absence
    # of it has to block a drop rather than permit one.
    def version_matchable?(entry, ranges)
      !Array(entry["versions"]).empty? || ranges.any? { |range| VERSION_RANGE_TYPES.include?(range["type"]) }
    end

    def encode(value)
      URI.encode_www_form_component(value.to_s)
    end
  end
end
