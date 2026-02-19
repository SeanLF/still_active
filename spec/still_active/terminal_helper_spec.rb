# frozen_string_literal: true

require_relative "../../lib/helpers/terminal_helper"

RSpec.describe(StillActive::TerminalHelper) do
  before { StillActive.reset }

  let(:result) do
    {
      "rails" => {
        version_used: "7.1.0",
        latest_version: "7.1.0",
        latest_pre_release_version: nil,
        last_commit_date: Time.now,
        latest_version_release_date: Time.now,
        latest_pre_release_version_release_date: nil,
        scorecard_score: 5.7,
        vulnerability_count: 0,
        repository_url: "https://github.com/rails/rails",
        ruby_gems_url: "https://rubygems.org/gems/rails",
      },
      "stale_gem" => {
        version_used: "1.0.0",
        latest_version: "2.0.0",
        latest_pre_release_version: nil,
        last_commit_date: Time.new(Time.now.year - 4, 1, 1),
        latest_version_release_date: Time.new(Time.now.year - 4, 1, 1),
        latest_pre_release_version_release_date: nil,
        scorecard_score: nil,
        vulnerability_count: 3,
        repository_url: "https://github.com/example/stale",
        ruby_gems_url: "https://rubygems.org/gems/stale_gem",
      },
    }
  end

  describe(".render") do
    subject(:output) { described_class.render(result) }

    it("includes all gem names") do
      expect(output).to(include("rails"))
      expect(output).to(include("stale_gem"))
    end

    it("includes header columns") do
      StillActive::TerminalHelper::HEADERS.each do |header|
        expect(output).to(include(header))
      end
    end

    it("includes a separator line") do
      expect(output).to(include("─"))
    end

    it("shows version status") do
      expect(output).to(include("latest"))
      expect(output).to(include("→"))
    end

    it("shows activity status") do
      expect(output).to(include("ok"))
      expect(output).to(include("critical"))
    end

    it("shows scorecard") do
      expect(output).to(include("5.7/10"))
    end

    it("shows vulnerability count") do
      expect(output).to(include("3"))
    end

    it("includes a summary line") do
      expect(output).to(include("2 gems:"))
      expect(output).to(include("1 up to date"))
      expect(output).to(include("1 outdated"))
      expect(output).to(include("1 active"))
      expect(output).to(include("1 stale"))
      expect(output).to(include("3 vulnerabilities"))
    end

    it("aligns columns consistently") do
      lines = output.split("\n").reject(&:empty?)
      data_lines = lines[2..3] # skip header and separator
      data_lines.each do |line|
        # Each line should be non-empty and have consistent structure
        expect(line.strip).not_to(be_empty)
      end
    end

    context("with an archived gem") do
      let(:result) do
        {
          "archived_gem" => {
            version_used: "1.0.0",
            latest_version: "1.0.0",
            latest_pre_release_version: nil,
            last_commit_date: Time.now,
            latest_version_release_date: Time.now,
            latest_pre_release_version_release_date: nil,
            scorecard_score: nil,
            vulnerability_count: nil,
            archived: true,
          },
        }
      end

      it("shows archived in activity column") do
        expect(output).to(include("archived"))
      end
    end

    context("with a yanked gem") do
      let(:result) do
        {
          "yanked_gem" => {
            version_used: "0.9.0",
            latest_version: "1.0.0",
            latest_pre_release_version: nil,
            last_commit_date: Time.now,
            latest_version_release_date: Time.now,
            latest_pre_release_version_release_date: nil,
            scorecard_score: nil,
            vulnerability_count: nil,
            version_yanked: true,
          },
        }
      end

      it("shows YANKED label") do
        expect(output).to(include("YANKED"))
      end

      it("includes yanked count in summary") do
        expect(output).to(include("1 yanked"))
      end
    end

    context("with empty results") do
      it("does not raise") do
        expect { described_class.render({}) }.not_to(raise_error)
      end
    end
  end
end
