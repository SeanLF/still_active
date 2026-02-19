# frozen_string_literal: true

require_relative "../../lib/helpers/markdown_helper"

RSpec.describe(StillActive::MarkdownHelper) do
  before { StillActive.reset }

  describe(".markdown_table_header_line") do
    subject(:header) { described_class.markdown_table_header_line }

    it("includes all column names") do
      ["activity", "OpenSSF", "vulns", "name"].each do |col|
        expect(header).to(include(col))
      end
    end

    it("includes the separator row") do
      expect(header).to(include("| ----"))
    end
  end

  describe(".markdown_table_body_line") do
    subject(:line) { described_class.markdown_table_body_line(gem_name: "rails", data: data) }

    let(:data) do
      {
        last_activity_warning_emoji: "",
        up_to_date_emoji: "✅",
        version_used: "7.1.0",
        version_used_release_date: Time.new(2024, 1, 15),
        latest_version: "7.1.0",
        latest_version_release_date: Time.new(2024, 1, 15),
        latest_pre_release_version: "8.0.0.rc1",
        latest_pre_release_version_release_date: Time.new(2024, 6, 1),
        repository_url: "https://github.com/rails/rails",
        ruby_gems_url: "https://rubygems.org/gems/rails",
        last_commit_date: Time.new(2024, 7, 1),
        scorecard_score: 5.7,
        vulnerability_count: 0,
      }
    end

    it("starts and ends with pipe") do
      expect(line).to(start_with("| "))
      expect(line).to(end_with(" |"))
    end

    it("includes the gem name as a markdown link") do
      expect(line).to(include("[rails](https://github.com/rails/rails)"))
    end

    it("includes version used with rubygems link") do
      expect(line).to(include("[7.1.0](https://rubygems.org/gems/rails/versions/7.1.0)"))
    end

    it("includes scorecard") do
      expect(line).to(include("5.7/10"))
    end

    it("includes success emoji for zero vulnerabilities") do
      expect(line).to(include("✅"))
    end

    it("includes last commit year/month") do
      expect(line).to(include("2024/07"))
    end

    context("when data is missing") do
      let(:data) do
        {
          last_activity_warning_emoji: nil,
          up_to_date_emoji: nil,
          version_used: nil,
          version_used_release_date: nil,
          latest_version: nil,
          latest_version_release_date: nil,
          latest_pre_release_version: nil,
          latest_pre_release_version_release_date: nil,
          repository_url: nil,
          ruby_gems_url: nil,
          last_commit_date: nil,
          scorecard_score: nil,
          vulnerability_count: nil,
        }
      end

      it("falls back to unsure emoji for nil values") do
        unsure = StillActive.config.unsure_emoji
        expect(line).to(include(unsure))
      end
    end

    context("when vulnerability count is nonzero with details") do
      let(:data) do
        {
          last_activity_warning_emoji: "",
          up_to_date_emoji: "✅",
          version_used: "1.0.0",
          version_used_release_date: Time.now,
          latest_version: "1.0.0",
          latest_version_release_date: Time.now,
          latest_pre_release_version: nil,
          latest_pre_release_version_release_date: nil,
          repository_url: "https://github.com/ex/gem",
          ruby_gems_url: "https://rubygems.org/gems/gem",
          last_commit_date: Time.now,
          scorecard_score: 5.0,
          vulnerability_count: 2,
          vulnerabilities: [
            { id: "GHSA-abc", aliases: ["CVE-2024-1234"], cvss3_score: 9.1 },
            { id: "GHSA-def", aliases: [], cvss3_score: 5.0 },
          ],
        }
      end

      it("shows count with severity and advisory IDs") do
        expect(line).to(include("2 (critical)"))
        expect(line).to(include("GHSA-abc"))
      end
    end
  end
end
