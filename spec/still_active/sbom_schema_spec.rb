# frozen_string_literal: true

require "json_schemer"

# The --sbom --json contract. Shared fields reference the Gemfile audit's schema,
# so they're resolved from the local file rather than fetched.
RSpec.describe("--sbom JSON Schema conformance") do # rubocop:disable RSpec/DescribeClass -- a published contract across the CLI's SBOM output
  def docs(file) = File.expand_path("../../docs/#{file}", __dir__)

  def schemer
    native = JSON.parse(File.read(docs("still_active.schema.json")))
    JSONSchemer.schema(
      Pathname.new(docs("still_active.sbom.schema.json")),
      ref_resolver: ->(uri) { native if uri.path.end_with?("/still_active.schema.json") }
    )
  end

  def emit(result, unassessable, health)
    captured = nil
    allow($stdout).to(receive(:puts)) { |arg| captured = arg }
    StillActive::CLI.new.send(:emit_sbom_json, result, unassessable, health)
    JSON.parse(captured)
  end

  let(:recent) { Time.now - (30 * 24 * 60 * 60) }

  # Every per-dependency field the SBOM path emits, across four dependencies,
  # plus an unassessable entry of each shape.
  let(:result) do
    {
      "npm/express@5.1.0" => {
        ecosystem: :npm, name: "express", version_used: "5.1.0", purl: "pkg:npm/express@5.1.0",
        production: true, direct: true, version_used_release_date: "2025-03-31T00:00:00Z",
        latest_version: "5.2.1", latest_version_release_date: "2026-01-01T00:00:00Z", libyear: 0.8,
        up_to_date: false, license: "MIT", deprecated: false, deprecation_reason: nil,
        repository_url: "https://github.com/expressjs/express", repository_source: "ecosyste.ms", last_commit_date: recent, archived: false,
        scorecard_score: 8.5, scorecard_maintained: 10, vulnerability_count: 1, vulnerabilities_checked: true,
        vulnerabilities: [{id: "CVE-2024-1", url: "https://example/x", title: "t", aliases: ["GHSA-x"], cvss3_score: 7.5, cvss3_vector: "AV:N", cvss2_score: nil, source: "osv", osv_severity: "HIGH", osv_cvss_score: 7.5, cvss_version: "3.1", cvss_vector: "CVSS:3.1/AV:N", fixed_versions: ["5.2.0"]}]
      },
      "pypi/oldlib@1.0.0" => {
        ecosystem: :pypi, name: "oldlib", version_used: "1.0.0", purl: "pkg:pypi/oldlib@1.0.0",
        direct: false, dependency_path: ["app", "oldlib"], vulnerability_count: 0, vulnerabilities_checked: false, vulnerabilities: [],
        latest_version_release_date: "2019-01-01T00:00:00Z", deprecated: true, deprecation_reason: "use newlib",
        poison: true, poison_severity: :critical, poison_security_relevant: true, poison_below_fix: true,
        constraints: [{dependency: "urllib3", requirement: "< 2.0", dep_latest: "2.5.0", majors_behind: 1, kind: :ceiling, capped_dep_vulnerable: true, capped_below_fix: true, below_fix_advisory: "CVE-2024-9", below_fix_fixed_in: "1.26.19"}]
      },
      "pypi/ceiling@2.0.0" => {
        ecosystem: :pypi, name: "ceiling", version_used: "2.0.0", purl: "pkg:pypi/ceiling@2.0.0", vulnerability_count: 0, vulnerabilities_checked: true, vulnerabilities: [],
        language_ceiling: {runtime: "Python", requirement: "< 3.9", eol_forced: true, severity: :critical, ceiling_version: "3.8", ceiling_eol_date: Time.new(2024, 10, 7, 0, 0, 0, "+00:00"), oldest_supported: "3.10", latest_stable: "3.14.0", fixed_by_upgrade: false, upgrade_blocked: true}
      },
      "npm/ghost@9.9.9" => {
        ecosystem: :npm, name: "ghost", version_used: "9.9.9", purl: "pkg:npm/ghost@9.9.9", version_unresolved: true, repository_unavailable: true,
        vulnerability_count: 0, vulnerabilities_checked: true, vulnerabilities: []
      }
    }
  end

  let(:unassessable) do
    [
      {ecosystem: nil, name: "vendored", reason: :no_purl},
      {ecosystem: "npm", name: "@acme/internal", version: "1.0.0", reason: :private_registry, repository_url: "https://npm.acme.example", purl: "pkg:npm/%40acme/internal@1.0.0", production: true, direct: true, dependency_path: ["app"]},
      {ecosystem: :pypi, name: "flask", version: "2.0.0", reason: :assessment_error, error: "Net::ReadTimeout: timed out"}
    ]
  end

  let(:health) { StillActive::SourceHealth::Report.new(advisory_schema_ok: true, stale_ecosystems: [:go]) }

  it("emits JSON that validates against the published SBOM schema, and says so") do
    payload = emit(result, unassessable, health)

    errors = schemer.validate(payload).to_a
    expect(errors).to(be_empty, errors.map { "#{_1["data_pointer"]}: #{_1["type"]} (#{_1["data"].inspect})" }.join("\n"))
    expect(payload["$schema"]).to(eq(StillActive::CLI::SBOM_SCHEMA_URL))
  end

  # additionalProperties: false only guards a field something actually emits.
  it("exercises every dependency field the schema defines") do
    payload = emit(result, unassessable, health)
    defined = JSON.parse(File.read(docs("still_active.sbom.schema.json"))).dig("$defs", "dependency", "properties").keys
    emitted = payload["dependencies"].values.flat_map(&:keys).uniq

    expect(defined - emitted).to(be_empty, "never exercised: #{(defined - emitted).join(", ")}")
  end

  it("rejects a field the schema doesn't define") do
    payload = emit(result, unassessable, health)
    payload["dependencies"]["npm/express@5.1.0"]["surprise"] = 1

    expect(schemer.valid?(payload)).to(be(false))
  end
end
