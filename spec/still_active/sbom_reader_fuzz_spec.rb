# frozen_string_literal: true

# "Never raises" fuzz suite for SbomReader. SbomReader's docstring promises that a
# missing/malformed SBOM or a bad PURL degrades to empty/unassessable -- it must
# never backtrace, because one crash in --sbom mode drops EVERY other dependency's
# verdict. This is the regression net for PR #129: PackageURL.parse raises a BARE
# ArgumentError (not only the InvalidPackageURL subclass) on inputs like
# `pkg:npm/@1.0.0` and `pkg:npm/%zz@1.0.0`, common in real Syft/Trivy output.
#
# Fail-first check (run once, by hand): narrow the rescue in classify_purl back to
# `rescue PackageURL::InvalidPackageURL` and the "malformed PURLs" example below
# goes red on `pkg:npm/@1.0.0` / `pkg:npm/%zz@1.0.0`; restore the broad `ArgumentError`
# and it is green again.
RSpec.describe(StillActive::SbomReader) do
  # A one-component CycloneDX doc whose single library carries `purl`.
  def one_lib(purl, name: "candidate")
    { "bomFormat" => "CycloneDX", "components" => [{ "type" => "library", "name" => name, "purl" => purl }] }.to_json
  end

  # A known-good library plus a suspect one, so we can prove the good dependency
  # still resolves while the bad one is surfaced (never silently dropped, never a
  # crash that takes the good one down with it).
  def good_and(purl)
    {
      "bomFormat" => "CycloneDX",
      "components" => [
        { "type" => "library", "name" => "lodash", "purl" => "pkg:npm/lodash@4.17.21" },
        { "type" => "library", "name" => "suspect", "purl" => purl },
      ],
    }.to_json
  end

  # The specific bug shapes from PR #129 plus the surrounding malformed-PURL family.
  # `pkg:npm/@1.0.0` and `pkg:npm/%zz@1.0.0` raise a BARE ArgumentError; the others
  # raise PackageURL::InvalidPackageURL (an ArgumentError subclass), and `@@@@@@`
  # parses but carries no version. All must degrade to an unassessable entry.
  def malformed_purls
    [
      "pkg:npm/@1.0.0",    # empty name after namespace -> bare ArgumentError (PR #129)
      "pkg:npm/%zz@1.0.0", # bad percent-encoding -> bare ArgumentError (PR #129)
      "pkg:",
      "pkg:npm",
      "pkg:/@",
      "not-a-purl",
      "",
      "pkg:npm/%",
      "pkg:npm/@@@@@@",
      "pkg:npm/%2",
    ]
  end

  # Exotic but SPEC-VALID purls: they must parse cleanly (no raise) and either land
  # in dependencies (supported ecosystem + version) or unassessable, never crash.
  def exotic_valid_purls
    [
      "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
      "pkg:golang/github.com/open-telemetry/opentelemetry-go/exporters/otlp@1.2.3",
      "pkg:npm/%40scope/deeply/nested@1.0.0",
      "pkg:pypi/n%C3%A4me@1.0.0", # percent-encoded unicode name
      "pkg:cargo/serde_derive@1.0.197",
      "pkg:gem/nokogiri@1.16.0?platform=java",
      "pkg:golang/gopkg.in/yaml.v3@3.0.1",
      "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2?type=jar",
    ]
  end

  it "surfaces every malformed PURL as unassessable without raising, keeping the good dep (PR #129)" do
    malformed_purls.each do |purl|
      result = nil
      expect { result = described_class.parse_string(good_and(purl)) }.not_to(
        raise_error, "raised on purl=#{purl.inspect}"
      )
      expect(result).to(be_a(described_class::Result), "non-Result for purl=#{purl.inspect}")
      # The good dependency is untouched by the bad neighbour.
      expect(result.dependencies.map { |d| d[:name] }).to(eq(["lodash"]), "good dep dropped by purl=#{purl.inspect}")
      # The bad component is surfaced, never silently dropped: :malformed_purl for a
      # parse error, :no_purl for the empty string, :no_version for a purl that parses
      # but carries no version. The contract is that it lands in unassessable.
      expect(result.unassessable.size).to(eq(1), "bad component not surfaced for purl=#{purl.inspect}")
      reason = result.unassessable.first[:reason]
      expect(reason).to(
        eq(:malformed_purl).or(eq(:no_purl)).or(eq(:no_version)), "unexpected reason #{reason.inspect} for purl=#{purl.inspect}"
      )
    end
  end

  it "parses exotic-but-valid PURLs without raising and never loses the component" do
    exotic_valid_purls.each do |purl|
      result = nil
      expect { result = described_class.parse_string(one_lib(purl)) }.not_to(
        raise_error, "raised on purl=#{purl.inspect}"
      )
      expect(result).to(be_a(described_class::Result), "non-Result for purl=#{purl.inspect}")
      # A library component is always accounted for: assessed, or surfaced -- never dropped.
      expect(result.dependencies.size + result.unassessable.size).to(eq(1), "component lost for purl=#{purl.inspect}")
    end
  end

  describe "malformed CycloneDX documents degrade to an empty Result" do
    {
      "not-json" => "not json at all",
      "empty object" => "{}",
      "components is a string" => '{"components":"x"}',
      "components is a number" => '{"components":42}',
      "null body" => "null",
      "bare array" => "[]",
    }.each do |label, body|
      it "returns an empty Result for #{label}" do
        result = nil
        expect { result = described_class.parse_string(body) }.not_to(raise_error)
        expect(result).to(eq(described_class::Result.new(dependencies: [], unassessable: [])))
      end
    end

    it "handles heterogeneous component entries (empty hash, bare library, non-hash) without raising" do
      body = '{"components":[{}, {"type":"library"}, "not-a-hash", 7, null]}'
      result = nil
      expect { result = described_class.parse_string(body) }.not_to(raise_error)
      expect(result).to(be_a(described_class::Result))
      # The {"type":"library"} with no purl is the only assessable-shaped entry; it
      # surfaces as no_purl. The rest are non-library noise and are dropped by design.
      expect(result.unassessable.map { |u| u[:reason] }).to(eq([:no_purl]))
    end
  end

  it "survives a huge component array with bad PURLs interspersed (no raise, good deps intact)" do
    good = Array.new(3000) { |i| { "type" => "library", "name" => "pkg#{i}", "purl" => "pkg:npm/pkg#{i}@1.0.#{i}" } }
    bad = malformed_purls.map.with_index { |p, i| { "type" => "library", "name" => "bad#{i}", "purl" => p } }
    body = { "bomFormat" => "CycloneDX", "components" => good.concat(bad) }.to_json
    result = nil
    expect { result = described_class.parse_string(body) }.not_to(raise_error)
    expect(result.dependencies.size).to(eq(3000))
    expect(result.unassessable.size).to(eq(bad.size))
  end

  # Bounded randomized sweep: faker-generated garbage as both purl and name. The
  # contract under test is only "never raises, always a Result" -- we do not assert
  # a classification for arbitrary strings. Deterministic seed so a failure is
  # reproducible; the offending input is printed in the failure message.
  it "never raises on 50 faker-generated garbage components" do
    seed = 20_260_705
    rng = Random.new(seed)
    Faker::Config.random = rng
    50.times do |i|
      purl = [
        Faker::Lorem.characters(number: rng.rand(0..60)),
        Faker::Internet.url,
        "pkg:#{Faker::Lorem.word}/#{Faker::Internet.slug}@#{Faker::App.semantic_version}",
        "pkg:npm/#{Faker::Lorem.characters(number: rng.rand(0..20))}@#{Faker::Lorem.word}",
      ].sample(random: rng)
      name = Faker::Lorem.characters(number: rng.rand(0..30))
      body = one_lib(purl, name: name)

      result = nil
      expect { result = described_class.parse_string(body) }.not_to(
        raise_error, "iteration #{i} (seed #{seed}) raised on purl=#{purl.inspect} name=#{name.inspect}"
      )
      expect(result).to(be_a(described_class::Result), "iteration #{i} returned a non-Result for purl=#{purl.inspect}")
      # A library component is never silently dropped: it is assessed or surfaced.
      expect(result.dependencies.size + result.unassessable.size).to(
        eq(1), "iteration #{i} dropped the component for purl=#{purl.inspect}"
      )
    end
  end

  it "read/read_string never raise and return arrays for malformed input" do
    expect { expect(described_class.read("spec/fixtures/sbom/does-not-exist.json")).to(eq([])) }.not_to(raise_error)
    expect { expect(described_class.read_string("garbage")).to(eq([])) }.not_to(raise_error)
    malformed_purls.each do |purl|
      expect { described_class.read_string(one_lib(purl)) }.not_to(raise_error, "read_string raised on purl=#{purl.inspect}")
    end
  end
end
