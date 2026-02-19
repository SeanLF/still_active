# frozen_string_literal: true

require_relative "../../lib/still_active/core_ext"

using StillActive::CoreExt

RSpec.describe(StillActive::EmojiHelper) do
  describe("#inactive_gem_emoji") do
    let(:now) { Time.now }
    let(:hash_keys) { [:last_commit_date, :latest_version_release_date, :latest_pre_release_version_release_date] }
    let(:test_cases) do
      [
        :no_warning_range_end,
        :warning_range_end,
      ]
        .map { |method| StillActive.config.public_send(method) }
        .unshift(0)
        .push(StillActive.config.warning_range_end + 1)
        .repeated_permutation(3)
        .to_a
        .unshift([nil, 0, 0])
        .push([nil, nil, nil])
        .map do |ary|
          times = ary.map do |num|
            if num.nil?
              nil
            elsif num.zero?
              now
            else
              now - num.years + 1.days
            end
          end
          hash_keys
            .zip(times)
            .to_h
        end
    end
    let(:expected_results) do
      Array.new(43) { "" }.push(
        Array.new(2) { StillActive.config.warning_emoji },
        Array.new(2) { "" },
        Array.new(2) { StillActive.config.warning_emoji },
        Array.new(10) { "" },
        Array.new(2) { StillActive.config.warning_emoji },
        Array.new(2) { "" },
        Array.new(1) { StillActive.config.warning_emoji },
        Array.new(1) { StillActive.config.critical_warning_emoji },
        Array.new(1) { StillActive.config.unsure_emoji },
      ).flatten
    end

    it("returns the expected emoji") do
      test_cases.each_with_index do |result_hash, index|
        subject = described_class.inactive_gem_emoji(result_hash)
        expected_result = expected_results[index]

        expect(subject).to(eq(expected_result))
      end
    end
  end

  describe("#using_latest_emoji") do
    let(:test_cases) { [nil, false, true].repeated_permutation(2).to_a }
    let(:hash_keys) { [:using_last_release, :using_last_pre_release] }
    let(:expected_results) do
      [
        StillActive.config.unsure_emoji,
        StillActive.config.warning_emoji,
        StillActive.config.futurist_emoji,
        StillActive.config.warning_emoji,
        StillActive.config.warning_emoji,
        StillActive.config.futurist_emoji,
        StillActive.config.success_emoji,
        StillActive.config.success_emoji,
        StillActive.config.futurist_emoji,
      ]
    end

    it("returns the expected emoji") do
      test_cases.each_with_index do |test_case, index|
        params = hash_keys.zip(test_case).to_h
        subject = described_class.using_latest_emoji(**params)
        expected_result = expected_results[index]

        expect(subject).to(eq(expected_result))
      end
    end
  end
end
