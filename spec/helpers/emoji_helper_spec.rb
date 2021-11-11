# frozen_string_literal: true

require "active_support/core_ext/integer/time"

RSpec.describe(StillActive::EmojiHelper) do
  describe("#inactive_gem_emoji") do
    let(:now) { Time.now }
    let(:test_cases) do
      [
        :safe_range_end,
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
              now - num.year + 1.day
            end
          end
          [:last_commit_date, :latest_version_release_date, :latest_pre_release_version_release_date]
            .zip(times)
            .to_h
        end
    end
    let(:expected_results) do
      43.times.map { "" }.push(
        2.times.map { StillActive.config.warning_emoji },
        2.times.map { "" },
        2.times.map { StillActive.config.warning_emoji },
        10.times.map { "" },
        2.times.map { StillActive.config.warning_emoji },
        2.times.map { "" },
        1.times.map { StillActive.config.warning_emoji },
        1.times.map { StillActive.config.critical_warning_emoji },
        1.times.map { StillActive.config.unsure_emoji },
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
        params = [:using_last_release, :using_last_pre_release].zip(test_case).to_h
        subject = described_class.using_latest_emoji(**params)
        expected_result = expected_results[index]

        expect(subject).to(eq(expected_result))
      end
    end
  end
end
