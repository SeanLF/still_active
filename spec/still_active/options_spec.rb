# frozen_string_literal: true

require_relative "../../lib/still_active/options"

RSpec.describe(StillActive::Options) do
  before { StillActive.reset }

  describe("#parse!") do
    it("sets output format to json") do
      described_class.new.parse!(["--json", "--gems=rails"])
      expect(StillActive.config.output_format).to(eq(:json))
    end

    it("sets output format to terminal") do
      described_class.new.parse!(["--terminal", "--gems=rails"])
      expect(StillActive.config.output_format).to(eq(:terminal))
    end

    it("sets output format to markdown") do
      described_class.new.parse!(["--markdown", "--gems=rails"])
      expect(StillActive.config.output_format).to(eq(:markdown))
    end

    it("sets gems from comma-separated list") do
      described_class.new.parse!(["--gems=rails,nokogiri"])
      expect(StillActive.config.gems).to(eq([{ name: "rails" }, { name: "nokogiri" }]))
    end

    it("sets gemfile path") do
      described_class.new.parse!(["--gemfile=/tmp/Gemfile"])
      expect(StillActive.config.gemfile_path).to(eq("/tmp/Gemfile"))
    end

    it("sets parallelism") do
      described_class.new.parse!(["--simultaneous-requests=5", "--gems=rails"])
      expect(StillActive.config.parallelism).to(eq(5))
    end

    it("sets fail-if-critical flag") do
      described_class.new.parse!(["--fail-if-critical", "--gems=rails"])
      expect(StillActive.config.fail_if_critical).to(be(true))
    end

    it("sets fail-if-warning flag") do
      described_class.new.parse!(["--fail-if-warning", "--gems=rails"])
      expect(StillActive.config.fail_if_warning).to(be(true))
    end

    it("sets github oauth token") do
      described_class.new.parse!(["--github-oauth-token=abc123", "--gems=rails"])
      expect(StillActive.config.github_oauth_token).to(eq("abc123"))
    end

    it("sets gitlab token") do
      described_class.new.parse!(["--gitlab-token=glpat-123", "--gems=rails"])
      expect(StillActive.config.gitlab_token).to(eq("glpat-123"))
    end

    it("sets safe range end") do
      described_class.new.parse!(["--safe-range-end=2", "--gems=rails"])
      expect(StillActive.config.no_warning_range_end).to(eq(2))
    end

    it("sets warning range end") do
      described_class.new.parse!(["--warning-range-end=5", "--gems=rails"])
      expect(StillActive.config.warning_range_end).to(eq(5))
    end

    it("sets fail-if-vulnerable to true when no severity given") do
      described_class.new.parse!(["--fail-if-vulnerable", "--gems=rails"])
      expect(StillActive.config.fail_if_vulnerable).to(be(true))
    end

    it("sets fail-if-vulnerable to severity string when given") do
      described_class.new.parse!(["--fail-if-vulnerable=high", "--gems=rails"])
      expect(StillActive.config.fail_if_vulnerable).to(eq("high"))
    end

    it("sets fail-if-outdated to float threshold") do
      described_class.new.parse!(["--fail-if-outdated=3", "--gems=rails"])
      expect(StillActive.config.fail_if_outdated).to(eq(3.0))
    end

    it("sets ignored gems from comma-separated list") do
      described_class.new.parse!(["--ignore=nokogiri,puma", "--gems=rails"])
      expect(StillActive.config.ignored_gems).to(eq(["nokogiri", "puma"]))
    end

    it("raises when fail-if-vulnerable severity is invalid") do
      expect { described_class.new.parse!(["--fail-if-vulnerable=banana", "--gems=rails"]) }
        .to(raise_error(ArgumentError, /severity must be one of/))
    end

    it("raises when both gemfile and gems are provided") do
      expect { described_class.new.parse!(["--gemfile=Gemfile", "--gems=rails"]) }
        .to(raise_error(ArgumentError, /provide gemfile or gems, not both/))
    end

    it("returns provided_gems flag when gems are given") do
      result = described_class.new.parse!(["--gems=rails"])
      expect(result[:provided_gems]).to(be(true))
    end

    it("returns provided_gemfile flag when gemfile is given") do
      result = described_class.new.parse!(["--gemfile=Gemfile"])
      expect(result[:provided_gemfile]).to(be(true))
    end
  end
end
