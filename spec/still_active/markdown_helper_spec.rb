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

    context("with a yanked version") do
      let(:data) do
        {
          last_activity_warning_emoji: "", up_to_date_emoji: "⚠️",
          version_used: "0.9.0", version_used_release_date: nil,
          latest_version: "1.0.0", latest_version_release_date: Time.now,
          latest_pre_release_version: nil, latest_pre_release_version_release_date: nil,
          repository_url: nil, ruby_gems_url: nil, last_commit_date: nil,
          scorecard_score: nil, vulnerability_count: nil, version_yanked: true,
        }
      end

      it("shows YANKED with critical emoji") do
        expect(line).to(include("YANKED"))
        expect(line).to(include(StillActive.config.critical_warning_emoji))
      end
    end

    context("with a git-sourced gem") do
      let(:data) do
        {
          last_activity_warning_emoji: "", up_to_date_emoji: nil,
          version_used: "0.5.0", source_type: :git,
          latest_version: nil, latest_version_release_date: nil,
          latest_pre_release_version: nil, latest_pre_release_version_release_date: nil,
          repository_url: nil, ruby_gems_url: nil, last_commit_date: nil,
          scorecard_score: nil, vulnerability_count: nil,
        }
      end

      it("shows version with source indicator") do
        expect(line).to(include("0.5.0 (git)"))
      end
    end

    context("with a path-sourced gem") do
      let(:data) do
        {
          last_activity_warning_emoji: "", up_to_date_emoji: nil,
          version_used: nil, source_type: :path,
          latest_version: nil, latest_version_release_date: nil,
          latest_pre_release_version: nil, latest_pre_release_version_release_date: nil,
          repository_url: nil, ruby_gems_url: nil, last_commit_date: nil,
          scorecard_score: nil, vulnerability_count: nil,
        }
      end

      it("shows source indicator without version") do
        expect(line).to(include("(path)"))
      end
    end

    context("with libyear and health score") do
      let(:data) do
        {
          last_activity_warning_emoji: "", up_to_date_emoji: "✅",
          version_used: "1.0.0", version_used_release_date: Time.now,
          latest_version: "1.0.0", latest_version_release_date: Time.now,
          latest_pre_release_version: nil, latest_pre_release_version_release_date: nil,
          repository_url: nil, ruby_gems_url: nil, last_commit_date: nil,
          scorecard_score: nil, vulnerability_count: 0,
          libyear: 2.5, health_score: 80,
        }
      end

      it("renders libyear and health values") do
        expect(line).to(include("2.5y"))
        expect(line).to(include("80/100"))
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

  describe(".ruby_line") do
    it("shows latest Ruby with success emoji") do
      info = { version: "3.4.0", latest_version: "3.4.0", libyear: nil, eol: false, eol_date: nil }
      line = described_class.ruby_line(info)
      expect(line).to(include("Ruby 3.4.0"))
      expect(line).to(include("latest"))
    end

    it("shows behind Ruby with warning emoji") do
      info = { version: "3.2.0", latest_version: "3.4.0", libyear: 1.5, eol: false, eol_date: nil }
      line = described_class.ruby_line(info)
      expect(line).to(include("1.5 libyears behind 3.4.0"))
      expect(line).to(include(StillActive.config.warning_emoji))
    end

    it("shows EOL Ruby with critical emoji and date") do
      info = { version: "3.1.0", latest_version: "3.4.0", libyear: 2.0, eol: true, eol_date: Time.new(2025, 3, 31) }
      line = described_class.ruby_line(info)
      expect(line).to(include("EOL 2025-03-31"))
      expect(line).to(include(StillActive.config.critical_warning_emoji))
    end

    it("shows EOL without date when eol_date is nil") do
      info = { version: "3.1.0", latest_version: "3.4.0", libyear: 2.0, eol: true, eol_date: nil }
      expect(described_class.ruby_line(info)).to(include("EOL,"))
    end
  end
end
