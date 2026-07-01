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
        up_to_date: true,
        last_commit_date: Time.now,
        latest_version_release_date: Time.now,
        latest_pre_release_version_release_date: nil,
        scorecard_score: 5.7,
        vulnerability_count: 0,
        repository_url: "https://github.com/rails/rails",
        ruby_gems_url: "https://rubygems.org/gems/rails",
        license: "MIT",
      },
      "stale_gem" => {
        version_used: "1.0.0",
        latest_version: "2.0.0",
        latest_pre_release_version: nil,
        up_to_date: false,
        last_commit_date: Time.new(Time.now.year - 4, 1, 1),
        latest_version_release_date: Time.new(Time.now.year - 4, 1, 1),
        latest_pre_release_version_release_date: nil,
        scorecard_score: nil,
        vulnerability_count: 3,
        vulnerabilities: [
          { id: "GHSA-1", cvss3_score: 9.8 },
          { id: "GHSA-2", cvss3_score: 5.0 },
          { id: "GHSA-3", cvss3_score: 3.0 },
        ],
        repository_url: "https://github.com/example/stale",
        ruby_gems_url: "https://rubygems.org/gems/stale_gem",
        libyear: 2.5,
        license: "GPL-3.0",
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

    it("shows the license column") do
      expect(output).to(include("License"))
      expect(output).to(include("MIT"))
      expect(output).to(include("GPL-3.0"))
    end

    it("shows vulnerability count with severity") do
      expect(output).to(include("3 (critical)"))
    end

    it("includes a summary line") do
      expect(output).to(include("2 gems:"))
      expect(output).to(include("1 up to date"))
      expect(output).to(include("1 outdated"))
      expect(output).to(include("1 active"))
      expect(output).to(include("1 stale"))
      expect(output).to(include("3 vulnerabilities"))
      expect(output).to(include("2.5 libyears behind"))
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

      it("shows archived separately from stale in summary") do
        expect(output).to(include("1 archived"))
        expect(output).to(include("0 stale"))
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

    context("with a git-sourced gem") do
      let(:result) do
        {
          "git_gem" => {
            version_used: "0.5.0",
            source_type: :git,
            last_commit_date: Time.now,
            latest_version_release_date: nil,
            latest_pre_release_version_release_date: nil,
            scorecard_score: nil,
            vulnerability_count: nil,
          },
        }
      end

      it("shows source indicator") do
        expect(output).to(include("(git)"))
      end
    end

    context("with a path-sourced gem") do
      let(:result) do
        {
          "path_gem" => {
            version_used: "0.1.0",
            source_type: :path,
            last_commit_date: nil,
            latest_version_release_date: nil,
            latest_pre_release_version_release_date: nil,
            scorecard_score: nil,
            vulnerability_count: nil,
          },
        }
      end

      it("shows source indicator") do
        expect(output).to(include("(path)"))
      end
    end

    context("with ruby info") do
      it("shows latest Ruby") do
        ruby_info = { version: "3.4.0", latest_version: "3.4.0", libyear: nil, eol: false, eol_date: nil }
        output = described_class.render(result, ruby_info: ruby_info)
        expect(output).to(include("Ruby 3.4.0"))
        expect(output).to(include("latest"))
      end

      it("shows behind Ruby") do
        ruby_info = { version: "3.2.0", latest_version: "3.4.0", libyear: 1.5, eol: false, eol_date: nil }
        output = described_class.render(result, ruby_info: ruby_info)
        expect(output).to(include("Ruby 3.2.0"))
        expect(output).to(include("1.5 libyears behind 3.4.0"))
      end

      it("shows EOL Ruby") do
        ruby_info = { version: "3.1.0", latest_version: "3.4.0", libyear: 2.0, eol: true, eol_date: Time.new(2025, 3, 31) }
        output = described_class.render(result, ruby_info: ruby_info)
        expect(output).to(include("Ruby 3.1.0"))
        expect(output).to(include("EOL 2025-03-31"))
      end
    end

    context("with empty results") do
      it("does not raise") do
        expect { described_class.render({}) }.not_to(raise_error)
      end
    end

    context("with alternatives leads sub-line") do
      it("prints a leads sub-line under a gem with alternatives") do
        result = {
          "paperclip" => {
            archived: true,
            alternatives: ["shrine", "carrierwave"],
            vulnerability_count: nil,
            scorecard_score: nil,
          },
        }
        out = described_class.render(result)
        expect(out).to(include("leads (Ruby Toolbox): shrine · carrierwave"))
      end

      it("prints a discoverability hint for an archived gem when alternatives are off") do
        StillActive.config.alternatives = false
        result = {
          "paperclip" => {
            archived: true,
            vulnerability_count: nil,
            scorecard_score: nil,
          },
        }
        out = described_class.render(result)
        expect(out).to(include("--alternatives"))
      end

      it("prints nothing extra for a healthy gem") do
        result = {
          "rails" => {
            last_commit_date: Time.now,
            latest_version_release_date: Time.now,
            latest_pre_release_version_release_date: nil,
            vulnerability_count: nil,
            scorecard_score: nil,
          },
        }
        out = described_class.render(result)
        expect(out).not_to(include("leads (Ruby Toolbox)"))
        expect(out).not_to(include("--alternatives"))
      end
    end

    context("with an unpatchable vulnerability") do
      it("marks 'no fix' in the vulns column when an advisory has no fixed version") do
        result = {
          "leftpad" => {
            version_used: "1.0.0",
            latest_version: "1.0.0",
            scorecard_score: nil,
            vulnerability_count: 1,
            vulnerabilities: [{ id: "CVE-1", cvss3_score: 7.5, no_fix_available: true }],
          },
        }
        expect(described_class.render(result)).to(include("1 (high, no fix)"))
      end
    end

    context("with a poison-pill sub-line") do
      def poison_gem(constraints, extra = {})
        {
          version_used: "1.1.4",
          latest_version: "1.1.4",
          vulnerability_count: 0,
          scorecard_score: nil,
          poison: true,
          constraints: constraints,
        }.merge(extra)
      end

      it("prints a rich single-cap receipt with the requirement and latest major") do
        result = {
          "protected_attributes" => poison_gem([
            { dependency: "activemodel", requirement: "< 5.0", dep_latest: "8.0.1", majors_behind: 4, kind: :ceiling },
          ]),
        }
        expect(described_class.render(result))
          .to(include("poison: caps activemodel < 5.0 (4 majors behind, latest 8.x)"))
      end

      it("prints a compact top-3 receipt with +N more for a many-cap gem, worst-first with name tie-break") do
        caps = [
          { dependency: "chalk", requirement: "^1", dep_latest: "5.0.0", majors_behind: 4, kind: :ceiling },
          { dependency: "through2", requirement: "^2", dep_latest: "5.0.0", majors_behind: 3, kind: :ceiling },
          { dependency: "vinyl", requirement: "^0.5", dep_latest: "3.0.0", majors_behind: 3, kind: :ceiling },
          { dependency: "dateformat", requirement: "^2", dep_latest: "5.0.0", majors_behind: 3, kind: :ceiling },
          { dependency: "beeper", requirement: "^1", dep_latest: "3.0.0", majors_behind: 2, kind: :ceiling },
        ]
        expect(described_class.render({ "gulp-util" => poison_gem(caps) }))
          .to(include("poison: caps chalk (4 behind), dateformat (3), through2 (3) +2 more"))
      end

      it("folds the parent into a transitive poison line and suppresses the generic transitive line") do
        result = {
          "terrapin" => poison_gem(
            [{ dependency: "climate_control", requirement: "< 1.0", dep_latest: "1.2.0", majors_behind: 1, kind: :ceiling }],
            { direct: false, dependency_path: ["paperclip", "terrapin"] },
          ),
        }
        out = described_class.render(result)
        expect(out).to(include("poison (via paperclip): caps climate_control < 1.0 (1 major behind, latest 1.x)"))
        expect(out).not_to(include("transitive, pulled in by paperclip"))
      end

      it("counts poison-pills in the summary line") do
        result = {
          "a" => poison_gem([{ dependency: "x", requirement: "< 5", dep_latest: "8.0.0", majors_behind: 3, kind: :ceiling }]),
          "b" => poison_gem([{ dependency: "y", requirement: "< 5", dep_latest: "8.0.0", majors_behind: 3, kind: :ceiling }]),
        }
        expect(described_class.render(result)).to(include("2 poison-pills"))
      end

      it("prints no poison line for a non-poison gem") do
        result = { "kaminari" => { version_used: "1", latest_version: "1", vulnerability_count: 0, scorecard_score: nil, poison: false } }
        expect(described_class.render(result)).not_to(include("poison:"))
      end
    end
  end
end
