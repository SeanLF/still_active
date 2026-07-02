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

    context("when an advisory has no fixed version") do
      let(:data) do
        {
          last_activity_warning_emoji: "",
          up_to_date_emoji: "✅",
          version_used: "1.0.0",
          latest_version: "1.0.0",
          version_used_release_date: Time.now,
          latest_version_release_date: Time.now,
          latest_pre_release_version: nil,
          latest_pre_release_version_release_date: nil,
          repository_url: nil,
          ruby_gems_url: nil,
          last_commit_date: nil,
          scorecard_score: nil,
          vulnerability_count: 1,
          vulnerabilities: [{ id: "CVE-1", aliases: [], cvss3_score: 7.5, no_fix_available: true }],
        }
      end

      it("marks 'no fix' alongside the severity") do
        expect(line).to(include("1 (high, no fix)"))
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

  describe(".poison_section") do
    def poison_gem(constraints, extra = {})
      { source_type: :rubygems, poison: true, constraints: constraints }.merge(extra)
    end

    it("lists a poison gem's worst caps with requirement and latest major") do
      result = {
        "protected_attributes" => poison_gem([
          { dependency: "activemodel", requirement: "< 5.0", dep_latest: "8.0.1", majors_behind: 4, kind: :ceiling },
        ]),
      }
      out = described_class.poison_section(result)
      expect(out).to(include("**Poison-pill findings**"))
      expect(out).to(include("`protected_attributes` caps `activemodel` `< 5.0` (4 majors behind, latest 8.x)"))
    end

    it("shows the worst 3 caps + total for a many-cap gem, worst-first with name tie-break") do
      caps = [
        { dependency: "chalk", requirement: "^1", dep_latest: "5.0.0", majors_behind: 4, kind: :ceiling },
        { dependency: "through2", requirement: "^2", dep_latest: "5.0.0", majors_behind: 3, kind: :ceiling },
        { dependency: "vinyl", requirement: "^0.5", dep_latest: "3.0.0", majors_behind: 3, kind: :ceiling },
        { dependency: "dateformat", requirement: "^2", dep_latest: "5.0.0", majors_behind: 3, kind: :ceiling },
      ]
      out = described_class.poison_section({ "gulp-util" => poison_gem(caps) })
      expect(out).to(include("`chalk` `^1` (4 majors behind, latest 5.x), `dateformat` `^2` (3), `through2` `^2` (3) — 4 total"))
    end

    it("names the direct parent for a transitive poison gem") do
      result = {
        "terrapin" => poison_gem(
          [{ dependency: "climate_control", requirement: "< 1.0", dep_latest: "1.2.0", majors_behind: 1, kind: :ceiling }],
          { direct: false, dependency_path: ["paperclip", "terrapin"] },
        ),
      }
      expect(described_class.poison_section(result))
        .to(include("`terrapin` via `paperclip` caps `climate_control` `< 1.0` (1 major behind, latest 1.x)"))
    end

    it("ranks poison findings worst-first with a tier label per bullet") do
      result = {
        "minor" => poison_gem([{ dependency: "a", requirement: "~> 2", dep_latest: "3.0.0", majors_behind: 1, kind: :ceiling }], { poison_severity: :note }),
        "blocker" => poison_gem([{ dependency: "b", requirement: "< 6", dep_latest: "9.0.0", majors_behind: 3, kind: :ceiling }], { poison_severity: :critical }),
      }
      out = described_class.poison_section(result)
      expect(out).to(include("**critical** `blocker`"))
      expect(out).to(include("**note** `minor`"))
      expect(out.index("blocker")).to(be < out.index("minor")) # worst-first
    end

    it("returns empty string when no gem is poison") do
      result = { "kaminari" => { source_type: :rubygems, poison: false } }
      expect(described_class.poison_section(result)).to(eq(""))
    end

    it("skips a poison gem with no constraints rather than emitting a dangling bullet") do
      result = { "odd" => { source_type: :rubygems, poison: true, constraints: [] } }
      expect(described_class.poison_section(result)).to(eq(""))
    end
  end

  describe(".language_ceiling_section") do
    def ceiling_gem(ceiling, extra = {})
      { source_type: :rubygems, latest_version: "4.0.0", language_ceiling: { runtime: "Ruby" }.merge(ceiling) }.merge(extra)
    end

    it("lists an EOL-forcing ceiling with the stranded Ruby, its EOL date, and the upgrade fix") do
      result = {
        "cfpropertylist" => ceiling_gem({
          requirement: "< 3.2",
          eol_forced: true,
          severity: :critical,
          ceiling_version: "3.1",
          ceiling_eol_date: Time.new(2025, 3, 31),
          oldest_supported: "3.3",
          latest_stable: "4.0.5",
          fixed_by_upgrade: true,
        }),
      }
      out = described_class.language_ceiling_section(result)
      expect(out).to(include("**Runtime ceiling findings**"))
      expect(out).to(include("**critical** `cfpropertylist` requires Ruby `< 3.2`, stranding you on end-of-life Ruby 3.1 (EOL 2025-03-31); upgrade to 4.0.0 to lift it"))
    end

    it("lists a latest-not-yet ceiling as a note without an upgrade fix") do
      result = {
        "somegem" => ceiling_gem(
          {
            requirement: "~> 3.3",
            eol_forced: false,
            severity: :note,
            oldest_supported: "3.3",
            latest_stable: "4.0.5",
            fixed_by_upgrade: false,
          },
          { latest_version: "1.0.0" },
        ),
      }
      out = described_class.language_ceiling_section(result)
      expect(out).to(include("**note** `somegem` requires Ruby `~> 3.3`, no Ruby 4.0.5 support yet"))
      expect(out).not_to(include("upgrade to"))
    end

    it("ranks ceilings worst-first (critical before note)") do
      result = {
        "minor" => ceiling_gem({ requirement: "~> 3.3", eol_forced: false, severity: :note, oldest_supported: "3.3", latest_stable: "4.0.5", fixed_by_upgrade: false }, { latest_version: "1.0.0" }),
        "blocker" => ceiling_gem({ requirement: "< 3.2", eol_forced: true, severity: :critical, ceiling_version: "3.1", ceiling_eol_date: nil, oldest_supported: "3.3", latest_stable: "4.0.5", fixed_by_upgrade: false }),
      }
      out = described_class.language_ceiling_section(result)
      expect(out.index("blocker")).to(be < out.index("minor"))
    end

    it("returns empty string when no gem has a ceiling") do
      expect(described_class.language_ceiling_section({ "rails" => { source_type: :rubygems } })).to(eq(""))
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
