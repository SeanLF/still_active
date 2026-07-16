# frozen_string_literal: true

require "tempfile"
require_relative "../../lib/still_active/options"

RSpec.describe(StillActive::Options) do
  before { StillActive.reset }

  describe("#parse!") do
    it("sets output format to json") do
      described_class.new.parse!(["--json", "--gems=rails"])
      expect(StillActive.config.output_format).to(eq(:json))
    end

    it("sets sarif_path to the default file when --sarif is bare") do
      described_class.new.parse!(["--sarif", "--gems=rails"])
      expect(StillActive.config.sarif_path).to(eq("still_active.sarif.json"))
    end

    it("sets sarif_path to the given file") do
      described_class.new.parse!(["--sarif=/tmp/out.sarif.json", "--gems=rails"])
      expect(StillActive.config.sarif_path).to(eq("/tmp/out.sarif.json"))
    end

    it("sets sarif_path to '-' for stdout") do
      described_class.new.parse!(["--sarif=-", "--gems=rails"])
      expect(StillActive.config.sarif_path).to(eq("-"))
    end

    it("sets baseline_path when --baseline is given with an existing file") do
      Tempfile.create(["baseline", ".json"]) do |f|
        f.write('{"schema_version":1,"gems":{}}')
        f.flush
        described_class.new.parse!(["--baseline=#{f.path}", "--gems=rails"])
        expect(StillActive.config.baseline_path).to(eq(f.path))
      end
    end

    it("raises ArgumentError when --baseline points at a missing file") do
      expect { described_class.new.parse!(["--baseline=/no/such/file.json", "--gems=rails"]) }
        .to(raise_error(ArgumentError, /baseline file not found/))
    end

    it("sets output format to terminal") do
      described_class.new.parse!(["--terminal", "--gems=rails"])
      expect(StillActive.config.output_format).to(eq(:terminal))
    end

    it("sets output format to markdown") do
      described_class.new.parse!(["--markdown", "--gems=rails"])
      expect(StillActive.config.output_format).to(eq(:markdown))
    end

    it("sets gems from comma-separated list, marked direct") do
      described_class.new.parse!(["--gems=rails,nokogiri"])
      expect(StillActive.config.gems).to(eq([{name: "rails", direct: true}, {name: "nokogiri", direct: true}]))
    end

    it("enables direct-only with --direct-only") do
      described_class.new.parse!(["--direct-only"])
      expect(StillActive.config.direct_only).to(be(true))
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

    it("sets the ecosyste.ms polite-pool email") do
      described_class.new.parse!(["--ecosystems-email=dev@example.com", "--gems=rails"])
      expect(StillActive.config.ecosystems_email).to(eq("dev@example.com"))
    end

    it("sets artifactory token") do
      described_class.new.parse!(["--artifactory-token=art-token", "--gems=rails"])
      expect(StillActive.config.artifactory_token).to(eq("art-token"))
    end

    it("sets artifactory host") do
      described_class.new.parse!(["--artifactory-host=my-org.jfrog.io", "--gems=rails"])
      expect(StillActive.config.artifactory_host).to(eq("my-org.jfrog.io"))
    end

    it("sets safe range end") do
      described_class.new.parse!(["--safe-range-end=2", "--gems=rails"])
      expect(StillActive.config.no_warning_range_end).to(eq(2))
    end

    it("accepts a fractional safe range end (the default ok ceiling is 1.5 years)") do
      described_class.new.parse!(["--safe-range-end=1.5", "--gems=rails"])
      expect(StillActive.config.no_warning_range_end).to(eq(1.5))
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

    it("sets fail-if-language-ceiling to true when bare") do
      described_class.new.parse!(["--fail-if-language-ceiling", "--gems=rails"])
      expect(StillActive.config.fail_if_language_ceiling).to(be(true))
    end

    it("sets fail-if-language-ceiling to a tier symbol when given one") do
      described_class.new.parse!(["--fail-if-language-ceiling=note", "--gems=rails"])
      expect(StillActive.config.fail_if_language_ceiling).to(eq(:note))
    end

    it("raises when the fail-if-language-ceiling tier is invalid") do
      expect { described_class.new.parse!(["--fail-if-language-ceiling=banana", "--gems=rails"]) }
        .to(raise_error(ArgumentError, /tier must be one of/))
    end

    it("warns that fail-if-language-ceiling=warning is a no-op tier but still accepts it") do
      expect { described_class.new.parse!(["--fail-if-language-ceiling=warning", "--gems=rails"]) }
        .to(output(/no effect.*behaves as =critical/).to_stderr)
      expect(StillActive.config.fail_if_language_ceiling).to(eq(:warning))
    end

    it("sets ignored gems from comma-separated list") do
      described_class.new.parse!(["--ignore=nokogiri,puma", "--gems=rails"])
      expect(StillActive.config.ignored_gems).to(eq(["nokogiri", "puma"]))
    end

    it("raises when fail-if-vulnerable severity is invalid") do
      expect { described_class.new.parse!(["--fail-if-vulnerable=banana", "--gems=rails"]) }
        .to(raise_error(ArgumentError, /severity must be one of/))
    end

    it("raises when more than one of gemfile/gems/sbom are provided") do
      expect { described_class.new.parse!(["--gemfile=Gemfile", "--gems=rails"]) }
        .to(raise_error(ArgumentError, /provide only one of/))
    end

    it("enables alternatives with --alternatives") do
      described_class.new.parse!(["--alternatives"])
      expect(StillActive.config.alternatives).to(be(true))
    end

    it("enables the unreleased-commits signal with --unreleased-commits") do
      described_class.new.parse!(["--unreleased-commits"])
      expect(StillActive.config.unreleased_commits).to(be(true))
    end

    it("leaves unreleased_commits off by default") do
      described_class.new.parse!([])
      expect(StillActive.config.unreleased_commits).to(be(false))
    end

    it("returns provided_gems flag when gems are given") do
      result = described_class.new.parse!(["--gems=rails"])
      expect(result[:provided_gems]).to(be(true))
    end

    it("returns provided_gemfile flag when gemfile is given") do
      result = described_class.new.parse!(["--gemfile=Gemfile"])
      expect(result[:provided_gemfile]).to(be(true))
    end

    it("sets sbom_path and the provided_sbom flag when the SBOM file exists") do
      Tempfile.create(["sbom", ".json"]) do |file|
        result = described_class.new.parse!(["--sbom=#{file.path}"])
        expect(result[:provided_sbom]).to(be(true))
        expect(StillActive.config.sbom_path).to(eq(file.path))
      end
    end

    it("raises when the --sbom path does not exist") do
      expect { described_class.new.parse!(["--sbom=/no/such/sbom.json"]) }
        .to(raise_error(ArgumentError, /SBOM file not found/))
    end
  end
end
