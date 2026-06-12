# frozen_string_literal: true

require_relative "../../lib/helpers/markdown_helper"

RSpec.describe(StillActive::MarkdownHelper) do
  before { StillActive.reset }

  describe(".markdown_table_header_line") do
    subject(:header) { described_class.markdown_table_header_line }

    it("includes all column names") do
      ["activity", "OpenSSF", "vulns", "name", "license"].each do |col|
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
        license: "MIT",
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

    it("includes the license") do
      expect(line).to(include("MIT"))
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
          last_activity_warning_emoji: "",
          up_to_date_emoji: "⚠️",
          version_used: "0.9.0",
          version_used_release_date: nil,
          latest_version: "1.0.0",
          latest_version_release_date: Time.now,
          latest_pre_release_version: nil,
          latest_pre_release_version_release_date: nil,
          repository_url: nil,
          ruby_gems_url: nil,
          last_commit_date: nil,
          scorecard_score: nil,
          vulnerability_count: nil,
          version_yanked: true,
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
          last_activity_warning_emoji: "",
          up_to_date_emoji: nil,
          version_used: "0.5.0",
          source_type: :git,
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

      it("shows version with source indicator") do
        expect(line).to(include("0.5.0 (git)"))
      end
    end

    context("with a path-sourced gem") do
      let(:data) do
        {
          last_activity_warning_emoji: "",
          up_to_date_emoji: nil,
          version_used: nil,
          source_type: :path,
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

      it("shows source indicator without version") do
        expect(line).to(include("(path)"))
      end
    end

    context("with libyear") do
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
          repository_url: nil,
          ruby_gems_url: nil,
          last_commit_date: nil,
          scorecard_score: nil,
          vulnerability_count: 0,
          libyear: 2.5,
        }
      end

      it("renders libyear value") do
        expect(line).to(include("2.5y"))
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

  describe(".markdown_table_body_line with hostile metadata") do
    # Gem names, licences, and repo URLs come from untrusted registry/repo
    # metadata and are rendered into PR comments. A literal "|" must not add
    # table columns, and "[]" in a name must not forge a markdown link.
    def body_line(gem_name:, data:)
      described_class.markdown_table_body_line(gem_name: gem_name, data: data)
    end

    # A valid 11-column row has exactly 12 unescaped pipe delimiters.
    def delimiter_count(line)
      line.scan(/(?<!\\)\|/).length
    end

    let(:base_data) do
      {
        last_activity_warning_emoji: "",
        up_to_date_emoji: "✅",
        version_used: "1.0.0",
        latest_version: "1.0.0",
        repository_url: "https://github.com/ex/gem",
        ruby_gems_url: "https://rubygems.org/gems/gem",
        vulnerability_count: 0,
        license: "MIT",
      }
    end

    it("escapes a pipe in the gem name so the column count is preserved") do
      line = body_line(gem_name: "evil|name", data: base_data)
      expect(delimiter_count(line)).to(eq(12))
    end

    it("escapes a pipe in the licence so the column count is preserved") do
      line = body_line(gem_name: "gem", data: base_data.merge(license: "MIT | --:|--: | EVIL"))
      expect(delimiter_count(line)).to(eq(12))
    end

    it("escapes a pipe in the repository URL so the column count is preserved") do
      line = body_line(gem_name: "gem", data: base_data.merge(repository_url: "https://evil.test/a|b"))
      expect(delimiter_count(line)).to(eq(12))
    end

    it("escapes brackets in the gem name so no nested markdown link is forged") do
      line = body_line(gem_name: "[click](javascript:alert(1))", data: base_data)
      expect(line).not_to(include("[click](javascript:alert(1))"))
    end

    it("escapes a backslash in the gem name so it can't escape the closing bracket") do
      line = body_line(gem_name: "trail\\", data: base_data)
      expect(line).to(include("[trail\\\\](https://github.com/ex/gem)"))
    end

    it("escapes a pipe in a vulnerability id so the column count is preserved") do
      data = base_data.merge(
        vulnerability_count: 1,
        vulnerabilities: [{ id: "GHSA-a|b", aliases: [], cvss3_score: 5.0 }],
      )
      expect(delimiter_count(body_line(gem_name: "gem", data: data))).to(eq(12))
    end

    it("still renders a normal gem name as a clean markdown link") do
      line = body_line(gem_name: "rails", data: base_data.merge(repository_url: "https://github.com/rails/rails"))
      expect(line).to(include("[rails](https://github.com/rails/rails)"))
    end
  end

  describe(".alternatives_section") do
    it("lists alternatives for flagged gems") do
      result = { "paperclip" => { source_type: :rubygems, archived: true, alternatives: ["shrine", "carrierwave"] } }
      out = described_class.alternatives_section(result)
      expect(out).to(include("**Alternatives**"))
      expect(out).to(include("`paperclip`: shrine, carrierwave"))
    end

    it("is empty when no gems have alternatives") do
      result = { "paperclip" => { source_type: :rubygems, archived: true } }
      expect(described_class.alternatives_section(result)).to(eq(""))
    end

    it("is empty when the alternatives array is empty") do
      result = { "paperclip" => { source_type: :rubygems, archived: true, alternatives: [] } }
      expect(described_class.alternatives_section(result)).to(eq(""))
    end

    it("neutralises a newline in an alternative so the list can't be broken") do
      result = { "paperclip" => { source_type: :rubygems, archived: true, alternatives: ["shrine\ninjected"] } }
      out = described_class.alternatives_section(result)
      expect(out).not_to(include("shrine\ninjected"))
      expect(out).to(include("shrine injected"))
    end
  end

  describe(".transitive_section") do
    it("names the direct parent of a flagged transitive gem") do
      result = { "rack" => { source_type: :rubygems, archived: true, direct: false, dependency_path: ["rails", "actionpack", "rack"] } }
      out = described_class.transitive_section(result)
      expect(out).to(include("**Transitive findings**"))
      expect(out).to(include("`rack` via `rails`"))
    end

    it("ignores healthy transitive gems and direct gems") do
      result = {
        "healthy" => { source_type: :rubygems, direct: false, dependency_path: ["a", "healthy"] },
        "direct_archived" => { source_type: :rubygems, archived: true, direct: true },
      }
      expect(described_class.transitive_section(result)).to(eq(""))
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
