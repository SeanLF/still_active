# frozen_string_literal: true

RSpec.describe(StillActive::Assessment) do
  it("declares exactly the fields the published schemas define, less the two derived at output") do
    docs = File.expand_path("../../docs", __dir__)
    native = JSON.parse(File.read(File.join(docs, "still_active.schema.json"))).dig("$defs", "gem", "properties").keys
    sbom = JSON.parse(File.read(File.join(docs, "still_active.sbom.schema.json"))).dig("$defs", "dependency", "properties").keys

    expect(described_class::FIELDS.map(&:to_s)).to(match_array((native | sbom) - ["activity_level", "status"]))
  end

  # A typo'd or unregistered field is an error, not a quiet nil.
  it("refuses an unknown field, when building and when reading") do
    expect { described_class.from(name: "x", vulnerabilites_checked: true) }.to(raise_error(ArgumentError, /vulnerabilites_checked/))
    expect { described_class.from(name: "x")[:vulnerabilites_checked] }.to(raise_error(KeyError))
  end

  # The bug class this exists for: a key never set read as "fine" wherever a
  # consumer tested it for false.
  it("decides the answers a hash left out: advisories unchecked, repository check failed") do
    assessment = described_class.from(name: "partial", source_type: :rubygems)

    expect(assessment).to(have_attributes(vulnerabilities_checked: false, repository_check: "failed"))
    expect(StillActive::StatusHelper.gem_status(assessment)).to(eq(:unknown))
  end

  it("keeps the answers a hash did give") do
    assessment = described_class.from(name: "x", vulnerabilities_checked: true, repository_check: "answered")

    expect(assessment).to(have_attributes(vulnerabilities_checked: true, repository_check: "answered"))
  end

  # The JSON keeps its shape: a field absent from the hash stays absent.
  it("gives back only the fields the path set, plus the decided answers") do
    assessment = described_class.from(name: "x", archived: nil)

    expect(assessment.to_h).to(eq(name: "x", archived: nil, vulnerabilities_checked: false, repository_check: "failed"))
    expect(assessment.key?(:archived)).to(be(true))
    expect(assessment.key?(:license)).to(be(false))
    expect(JSON.parse(assessment.to_json)).to(eq(assessment.to_h.transform_keys(&:to_s)))
  end

  it("reads nested values, and records fields set later") do
    assessment = described_class.from(name: "x", language_ceiling: {severity: :critical})

    expect(assessment.dig(:language_ceiling, :severity)).to(eq(:critical))
    expect(assessment.dig(:constraints, :anything)).to(be_nil)
    expect(assessment.with(poison: true).to_h).to(include(poison: true))
  end
end
