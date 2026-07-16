# frozen_string_literal: true

require_relative "../../lib/helpers/semver_satisfaction"

# "Never raises, always tri-state" fuzz suite for SemverSatisfaction.evaluate. The
# primitive must return true/false/nil for ANY input -- it feeds the below-the-fix
# wall test, and a raise there would crash the poison correlator (which runs
# unguarded). semantic_range is a node-semver port fed adversarial strings here.
RSpec.describe(StillActive::SemverSatisfaction) do
  def evaluate(requirement, version, ecosystem)
    described_class.evaluate(requirement: requirement, version: version, ecosystem: ecosystem)
  end

  def tri_state = [true, false, nil]

  # Adversarial requirement/version strings: empty, blank, nil, unicode, huge,
  # epoch (PyPI `1!2.3.4`), build metadata, operator soup, partials.
  def adversarial_inputs
    [
      nil,
      "",
      "   ",
      "\t\n",
      "\u{1F600}",
      "näme",
      "1!2.3.4",
      "1.2.3+build.999",
      "1.2.3-alpha+001",
      "^",
      "~",
      "~>",
      ">=",
      "<=<",
      "=====",
      "||",
      ">=1.0 || garbage",
      "*",
      "x",
      "x.y.z",
      "1.x",
      "1.2.x",
      "1",
      "1.2",
      "1.2.3",
      "v1.2.3",
      "0.10.38",
      "-1",
      "01.02.03",
      "#{"1." * 200}0",
      "1.0.0-#{"x" * 4000}",
      ">=1.0, <1.5",
      ">= 1.0.0 <2.0.0",
      "1.2.3 - 2.3.4"
    ]
  end

  ecosystems = [:npm, :cargo, :unknown, nil, :rubygems].freeze

  describe "curated adversarial cross-product (requirement x version x ecosystem)" do
    ecosystems.each do |ecosystem|
      it "returns only true/false/nil for every adversarial pair under #{ecosystem.inspect}" do
        adversarial_inputs.each do |requirement|
          adversarial_inputs.each do |version|
            result = nil
            expect { result = evaluate(requirement, version, ecosystem) }.not_to(
              raise_error, "raised on req=#{requirement.inspect} ver=#{version.inspect} eco=#{ecosystem.inspect}"
            )
            expect(tri_state).to(
              include(result), "req=#{requirement.inspect} ver=#{version.inspect} eco=#{ecosystem.inspect} -> #{result.inspect}"
            )
          end
        end
      end
    end
  end

  describe "unmodelled ecosystems are always undecidable (nil), never a raise" do
    it "returns nil for ecosystems the primitive does not model, even with valid semver" do
      [:rubygems, :pypi, :maven, :go, :nuget, :unknown, nil, :made_up].each do |ecosystem|
        expect(evaluate("^1.0.0", "1.2.0", ecosystem)).to(be_nil)
      end
    end
  end

  # Bounded randomized sweep. Deterministic seed; the offending pair prints on
  # failure so any regression is reproducible without a property-testing gem.
  describe "randomized garbage sweep (faker)" do
    it "never raises and always returns tri-state across 50 faker-generated pairs" do
      seed = 20_260_705
      rng = Random.new(seed)
      Faker::Config.random = rng
      50.times do |i|
        requirement = [
          Faker::App.semantic_version,
          "^#{Faker::App.semantic_version}",
          "~> #{Faker::App.semantic_version}",
          Faker::Lorem.characters(number: rng.rand(0..24)),
          Faker::Internet.slug
        ].sample(random: rng)
        version = [
          Faker::App.semantic_version,
          "#{Faker::App.semantic_version}+#{Faker::Lorem.word}",
          Faker::Lorem.characters(number: rng.rand(0..16)),
          Faker::Number.number(digits: rng.rand(1..6)).to_s
        ].sample(random: rng)
        ecosystem = [:npm, :cargo].sample(random: rng)

        result = nil
        expect { result = evaluate(requirement, version, ecosystem) }.not_to(
          raise_error, "iteration #{i} (seed #{seed}) raised on req=#{requirement.inspect} ver=#{version.inspect} eco=#{ecosystem.inspect}"
        )
        expect(tri_state).to(
          include(result), "iteration #{i} (seed #{seed}) req=#{requirement.inspect} ver=#{version.inspect} eco=#{ecosystem.inspect} -> #{result.inspect}"
        )
      end
    end
  end
end
