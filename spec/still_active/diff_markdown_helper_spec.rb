# frozen_string_literal: true

require_relative "../../lib/helpers/diff_markdown_helper"
require_relative "../../lib/still_active/diff"

RSpec.describe(StillActive::DiffMarkdownHelper) do
  let(:empty_result) do
    StillActive::Diff::Result.new(
      added: [],
      removed: [],
      bumped: [],
      signal_changes: [],
      regressions: [],
      ruby: nil
    )
  end

  describe(".render with accepted regressions") do
    let(:accepted) do
      [StillActive::Diff::Accepted.new(
        regression: StillActive::Diff::Regression.new(kind: :new_gem_archived, gem: "simplecov-html", detail: "added gem points at archived repo"),
        reason: "dev-only coverage reporter"
      )]
    end

    it("lists them under an Accepted section with the reason, not as CI-failable") do
      md = described_class.render(empty_result, accepted: accepted)
      expect(md).to(include("Accepted (suppressed via .still_active.yml)"))
      expect(md).to(include("simplecov-html"))
      expect(md).to(include("dev-only coverage reporter"))
      expect(md).not_to(include("Regressions (CI-failable)"))
    end

    it("counts them separately in the summary line") do
      md = described_class.render(empty_result, accepted: accepted)
      expect(md).to(include("0 regressions"))
      expect(md).to(include("1 accepted"))
    end

    it("omits the accepted count when there are none") do
      expect(described_class.render(empty_result)).not_to(include("accepted"))
    end
  end

  describe(".render") do
    it("starts with a still_active diff heading") do
      expect(described_class.render(empty_result)).to(start_with("## still_active diff"))
    end

    it("emits a summary line with all section counts") do
      md = described_class.render(empty_result)
      expect(md).to(include("0 regressions"))
      expect(md).to(include("0 added"))
      expect(md).to(include("0 removed"))
    end

    it("does not emit empty sections when there are no entries") do
      md = described_class.render(empty_result)
      expect(md).not_to(include("### Regressions"))
      expect(md).not_to(include("### Added"))
      expect(md).not_to(include("### Removed"))
    end

    it("handles nil gem data in added/removed entries (malformed baseline)") do
      result = StillActive::Diff::Result.new(
        added: [StillActive::Diff::Added.new(name: "weird_added", data: nil)],
        removed: [StillActive::Diff::Removed.new(name: "weird_removed", data: nil)],
        bumped: [],
        signal_changes: [],
        regressions: [],
        ruby: nil
      )
      expect { described_class.render(result) }.not_to(raise_error)
    end

    context("with regressions") do
      let(:result) do
        StillActive::Diff::Result.new(
          added: [],
          removed: [],
          bumped: [],
          signal_changes: [],
          regressions: [
            StillActive::Diff::Regression.new(kind: :new_gem_archived, gem: "newly_added", detail: "added gem points at archived repo"),
            StillActive::Diff::Regression.new(kind: :new_vulnerability, gem: "untouched", detail: "0 -> 1 (CVE-new)")
          ],
          ruby: nil
        )
      end

      it("has a Regressions section listed first") do
        md = described_class.render(result)
        expect(md).to(include("### Regressions"))
        expect(md.index("### Regressions")).to(be < (md.index("### Bumps") || md.length))
      end

      it("lists each regression with kind and gem") do
        md = described_class.render(result)
        expect(md).to(include("new_gem_archived"))
        expect(md).to(include("newly_added"))
        expect(md).to(include("new_vulnerability"))
        expect(md).to(include("untouched"))
      end
    end

    context("with added gems") do
      let(:result) do
        StillActive::Diff::Result.new(
          added: [StillActive::Diff::Added.new(name: "new_gem", data: {"version_used" => "1.0", "archived" => true, "scorecard_score" => 7.5})],
          removed: [],
          bumped: [],
          signal_changes: [],
          regressions: [],
          ruby: nil
        )
      end

      it("lists added gems with version + key signals inline") do
        md = described_class.render(result)
        expect(md).to(include("### Added"))
        expect(md).to(include("new_gem"))
        expect(md).to(include("v1.0"))
        expect(md).to(include("archived"))
      end
    end

    context("with version bumps") do
      let(:result) do
        StillActive::Diff::Result.new(
          added: [],
          removed: [],
          bumped: [
            StillActive::Diff::Bumped.new(
              name: "rails",
              before_version: "7.0",
              after_version: "7.1",
              kind: :closed_vulns,
              before: {"vulnerability_count" => 1},
              after: {"vulnerability_count" => 0}
            )
          ],
          signal_changes: [],
          regressions: [],
          ruby: nil
        )
      end

      it("annotates bumps with the kind") do
        md = described_class.render(result)
        expect(md).to(include("### Version bumps"))
        expect(md).to(include("rails"))
        expect(md).to(include("7.0"))
        expect(md).to(include("7.1"))
        expect(md).to(include("closed vulns"))
      end
    end

    context("with ruby delta") do
      it("notes ruby version change") do
        result = StillActive::Diff::Result.new(
          added: [],
          removed: [],
          bumped: [],
          signal_changes: [],
          regressions: [],
          ruby: {version_changed: true, from: "3.3.0", to: "3.4.0", newly_eol: false}
        )
        md = described_class.render(result)
        expect(md).to(include("### Ruby"))
        expect(md).to(include("3.3.0"))
        expect(md).to(include("3.4.0"))
      end

      it("does not emit a Ruby section when version is unchanged and not newly EOL") do
        result = StillActive::Diff::Result.new(
          added: [],
          removed: [],
          bumped: [],
          signal_changes: [],
          regressions: [],
          ruby: {version_changed: false, from: "3.3.0", to: "3.3.0", newly_eol: false}
        )
        md = described_class.render(result)
        expect(md).not_to(include("### Ruby"))
      end
    end

    context("with hostile gem names (from a crafted lockfile or --baseline file)") do
      it("fences a backtick in a regression gem name so the code span can't break out") do
        result = StillActive::Diff::Result.new(
          added: [],
          removed: [],
          bumped: [],
          signal_changes: [],
          ruby: nil,
          regressions: [StillActive::Diff::Regression.new(kind: :archived, gem: "ev`il", detail: "x")]
        )
        # longest backtick run is 1, so a 2-backtick fence keeps the name intact
        expect(described_class.render(result)).to(include("``ev`il``"))
      end

      it("neutralises a newline in an added gem name so the bullet list can't be forged") do
        result = StillActive::Diff::Result.new(
          added: [StillActive::Diff::Added.new(name: "foo\n- INJECTED", data: {"version_used" => "1.0"})],
          removed: [],
          bumped: [],
          signal_changes: [],
          regressions: [],
          ruby: nil
        )
        expect(described_class.render(result)).not_to(include("foo\n- INJECTED"))
      end
    end
  end
end
