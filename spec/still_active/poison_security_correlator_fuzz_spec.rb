# frozen_string_literal: true

require_relative "../../lib/still_active/poison_security_correlator"

# "Never raises" fuzz suite for PoisonSecurityCorrelator.correlate. Per the release
# audit, correlate runs OUTSIDE any rescue in the workflow: a single raise here
# crashes the whole audit after every fetch has already been paid for. It mutates
# the result hash in place over the vulnerability/constraint data every provider
# assembled, so it must tolerate the messy SCALAR shapes real providers emit --
# the PR #129 class: a non-string advisory alias, a non-string id, a nil/non-string
# fixed_version, a non-string resolved version.
RSpec.describe(StillActive::PoisonSecurityCorrelator) do
  # Reachable malformed shapes: the containers are the arrays/hashes the pipeline
  # always builds, but the scalars inside are the garbage providers really return
  # (deps.dev aliases as bare strings vs objects, etc.). None of these must raise.
  reachable_malformed = {
    "missing keys entirely" => { "a" => {} },
    "nil values where scalars expected" => {
      "a" => { ecosystem: nil, name: nil, version_used: nil, constraints: nil, capped_deps: nil, vulnerabilities: nil, vulnerability_count: nil },
    },
    "empty constraints/vulnerabilities arrays" => {
      "a" => { ecosystem: :pypi, name: "x", constraints: [], vulnerabilities: [], vulnerability_count: 0 },
    },
    "non-string dependency + nil requirement in a constraint" => {
      "a" => { ecosystem: :pypi, name: "x", constraints: [{ dependency: 123, requirement: nil, majors_behind: nil }], vulnerability_count: 1, vulnerabilities: [{ id: nil }] },
    },
    "non-string resolved version + non-string requirement (nested)" => {
      "a" => { ecosystem: :npm, name: "capper", version_used: 123, capped_deps: [{ dependency: "dep", requirement: 999 }] },
      "b" => { ecosystem: :npm, name: "dep", version_used: [1, 2], vulnerabilities: [{ id: "V", fixed_versions: [nil, 123, "2.0.0"], cvss3_score: 9.1 }] },
    },
    "non-string advisory id + aliases (PR #129 alias shape)" => {
      "a" => { ecosystem: :pypi, name: "capper", constraints: [{ dependency: "dep", requirement: "< 5", majors_behind: 3, kind: :ceiling }] },
      "b" => { ecosystem: :pypi, name: "dep", version_used: 1, vulnerability_count: 1, vulnerabilities: [{ id: 123, aliases: [456, nil, {}, "CVE-2026-1"], fixed_versions: [789, nil], cvss3_score: 8.1 }] },
    },
    "epoch / unparseable fixed_versions" => {
      "a" => { ecosystem: :pypi, name: "capper", version_used: "1!2.3", constraints: [{ dependency: "dep", requirement: "< 5", majors_behind: 3, kind: :ceiling }] },
      "b" => { ecosystem: :pypi, name: "dep", version_used: "1!2.3", vulnerability_count: 1, vulnerabilities: [{ id: "CVE-x", fixed_versions: ["1!9.9.9", "garbage"], cvss3_score: 9.8 }] },
    },
    "vulnerability_count positive but vulnerabilities absent" => {
      "a" => { ecosystem: :pypi, name: "x", vulnerability_count: 3, constraints: [{ dependency: "dep", requirement: "< 5" }] },
    },
  }.freeze

  describe "reachable malformed result objects never raise (PR #129 scalar shapes)" do
    reachable_malformed.each do |label, result_object|
      it "tolerates: #{label}" do
        expect { described_class.correlate(deep_dup(result_object)) }.not_to(raise_error)
      end
    end
  end

  # Bounded randomized sweep: well-shaped containers (arrays of hashes, as the
  # pipeline guarantees) filled with faker scalar garbage. Deterministic seed; the
  # offending object prints on failure.
  describe "randomized garbage sweep (faker)" do
    it "never raises across 50 faker-generated result objects" do
      seed = 20_260_705
      rng = Random.new(seed)
      Faker::Config.random = rng
      50.times do |i|
        object = build_fuzz_result(rng)
        expect { described_class.correlate(object) }.not_to(
          raise_error, "iteration #{i} (seed #{seed}) raised on:\n#{object.inspect}"
        )
      end
    end

    def build_fuzz_result(rng)
      eco = [:pypi, :rubygems, :npm, :cargo, nil].sample(random: rng)
      capper = {
        ecosystem: eco,
        name: Faker::Lorem.word,
        version_used: [Faker::App.semantic_version, nil, rng.rand(100)].sample(random: rng),
        constraints: fuzz_constraints(rng),
      }
      capper[:capped_deps] = fuzz_capped_deps(rng) if rng.rand < 0.5
      dep = {
        ecosystem: eco,
        name: Faker::Lorem.word,
        version_used: [Faker::App.semantic_version, nil].sample(random: rng),
        vulnerability_count: rng.rand(0..3),
        vulnerabilities: fuzz_vulns(rng),
      }
      { "a" => capper, "b" => dep }
    end

    def fuzz_constraints(rng)
      Array.new(rng.rand(0..2)) do
        { dependency: [Faker::Lorem.word, rng.rand(9)].sample(random: rng), requirement: ["< 5", nil, rng.rand(9)].sample(random: rng), majors_behind: rng.rand(0..4), kind: :ceiling }
      end
    end

    def fuzz_capped_deps(rng)
      Array.new(rng.rand(0..2)) do
        { dependency: Faker::Lorem.word, requirement: ["^1.0.0", "< 5", nil].sample(random: rng) }
      end
    end

    def fuzz_vulns(rng)
      Array.new(rng.rand(0..3)) do
        {
          id: [Faker::Internet.slug, nil, rng.rand(999)].sample(random: rng),
          aliases: [rng.rand(999), nil, "CVE-#{rng.rand(9999)}"].sample(rng.rand(0..3), random: rng),
          fixed_versions: [Faker::App.semantic_version, nil, rng.rand(9), "garbage"].sample(rng.rand(0..3), random: rng),
          cvss3_score: [Faker::Number.between(from: 0.0, to: 10.0), nil].sample(random: rng),
        }
      end
    end
  end

  # FOUND -- robustness gaps, NOT reachable from the current pipeline. correlate is
  # the one consumer that does NOT Array()-wrap data[:constraints] / data[:capped_deps]
  # the way markdown_helper, sarif_helper and terminal_helper all do, and it assumes
  # each vulnerabilities element is a Hash. The pipeline only ever assigns arrays of
  # hashes, so these are unreachable today -- but correlate runs unguarded, so the
  # asymmetry is worth a marker. These are `pending`: they raise now; the day someone
  # adds the Array()/Hash guard, RSpec flips them green and flags the pending removal.
  describe "structural invariant violations (pending: documented robustness gap)" do
    it "does not raise when :constraints is a non-array" do
      pending("FOUND: correlate iterates data[:constraints] without Array()-wrapping (siblings do). Unreachable from the pipeline; crashes the unguarded pass if it ever occurs.")
      expect { described_class.correlate({ "a" => { constraints: "nope", vulnerability_count: 1, vulnerabilities: [] } }) }.not_to(raise_error)
    end

    it "does not raise when :capped_deps is a non-array" do
      pending("FOUND: promote_nested_below_fix calls data.delete(:capped_deps).filter_map without Array()-wrapping.")
      expect { described_class.correlate({ "a" => { ecosystem: :npm, name: "x", capped_deps: "nope" } }) }.not_to(raise_error)
    end

    it "does not raise when a :vulnerabilities element is a non-hash" do
      pending("FOUND: candidate/every_copy_affected index vuln[:id] assuming each element is a Hash.")
      object = {
        "a" => { ecosystem: :pypi, name: "x", constraints: [{ dependency: "dep", requirement: "< 5" }] },
        "b" => { ecosystem: :pypi, name: "dep", vulnerability_count: 1, vulnerabilities: ["notahash", nil, 5], version_used: "1.0.0" },
      }
      expect { described_class.correlate(object) }.not_to(raise_error)
    end
  end

  # correlate mutates in place, so the fuzz sweep must not share frozen literals
  # across iterations; a shallow-enough deep dup for our hash/array/scalar shapes.
  def deep_dup(object)
    case object
    when Hash then object.transform_values { |v| deep_dup(v) }
    when Array then object.map { |v| deep_dup(v) }
    else object
    end
  end
end
