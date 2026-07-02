# frozen_string_literal: true

require "optparse"
require_relative "../helpers/constraint_helper"
require_relative "../helpers/cyclonedx_helper"
require_relative "../helpers/vulnerability_helper"

module StillActive
  class Options
    attr_accessor :options, :options_parser

    def initialize
      @options = {}
      @options_parser = OptionParser.new do |opts|
        add_banner(opts)
        add_tail_options(opts)
        add_gemfile_option(opts)
        add_gems_option(opts)
        add_sbom_option(opts)
        add_ignore_option(opts)
        add_output_options(opts)
        add_token_options(opts)
        add_parallelism_options(opts)
        add_range_options(opts)
        add_exit_options(opts)
        add_emoji_options(opts)
      end
    end

    def parse!(args)
      options_parser.parse!(args)
      validate_options
      options
    end

    private

    def validate_options
      inputs = [options[:provided_gemfile], options[:provided_gems], options[:provided_sbom]].compact
      raise ArgumentError, "provide only one of --gemfile, --gems, --sbom" if inputs.size > 1
      if options[:provided_sbom] && !File.exist?(StillActive.config.sbom_path)
        raise ArgumentError, "SBOM file not found: #{StillActive.config.sbom_path}"
      end
      if options[:provided_baseline] && !File.exist?(StillActive.config.baseline_path)
        raise ArgumentError, "baseline file not found: #{StillActive.config.baseline_path}"
      end
    end

    def add_gemfile_option(opts)
      opts.on("--gemfile=GEMFILE", String, "path to gemfile") do |value|
        options[:provided_gemfile] = true
        StillActive.config { |config| config.gemfile_path = value }
      end
    end

    def add_gems_option(opts)
      opts.on("--gems=GEM,GEM2,...", Array, "Gem(s)") do |value|
        options[:provided_gems] = true
        # Explicitly named gems are direct by definition (the user chose them).
        StillActive.config { |config| config.gems = value.map { |g| { name: g, direct: true } } }
      end
    end

    def add_sbom_option(opts)
      opts.on("--sbom=PATH", String, "audit a CycloneDX SBOM cross-ecosystem (npm/pypi/cargo/go/maven/nuget) instead of a Gemfile; JSON output") do |value|
        options[:provided_sbom] = true
        StillActive.config { |config| config.sbom_path = value }
      end
    end

    def add_ignore_option(opts)
      opts.on("--ignore=GEM,GEM2,...", Array, "Gem(s) to exclude from pass/fail checks") do |value|
        StillActive.config { |config| config.ignored_gems = value }
      end
    end

    def add_output_options(opts)
      opts.on("--terminal", "Coloured terminal output (default in TTY)") { StillActive.config { |config| config.output_format = :terminal } }
      opts.on("--markdown", "Markdown table output") { StillActive.config { |config| config.output_format = :markdown } }
      opts.on("--json", "JSON output (default when piped)") { StillActive.config { |config| config.output_format = :json } }
      opts.on("--alternatives", "Suggest maintained alternatives (Ruby Toolbox leads) for archived/critical gems") { StillActive.config { |config| config.alternatives = true } }
      opts.on("--unreleased-commits", "Count commits on the default branch since the latest release (GitHub only; opt-in, one extra API call per gem)") { StillActive.config { |config| config.unreleased_commits = true } }
      opts.on("--direct-only", "Audit only direct (declared) dependencies, not the full transitive lockfile graph") { StillActive.config { |config| config.direct_only = true } }
      opts.on("--sarif[=PATH]", "SARIF 2.1.0 output for GitHub Code Scanning (default path: still_active.sarif.json; '-' for stdout). Overrides --terminal/--markdown/--json.") do |value|
        StillActive.config { |config| config.sarif_path = value || "still_active.sarif.json" }
      end
      opts.on("--baseline=PATH", String, "Compare current state to baseline still_active JSON; emit markdown deltas. Exits 1 on regressions.") do |value|
        options[:provided_baseline] = true
        StillActive.config { |config| config.baseline_path = value }
      end
      opts.on("--cyclonedx[=PATH]", "CycloneDX SBOM output (default to stdout; PATH to write a file). Overrides --terminal/--markdown/--json.") do |value|
        StillActive.config { |config| config.cyclonedx_path = value || "-" }
      end
      opts.on("--cyclonedx-version=VERSION", String, "CycloneDX spec version to emit: 1.6 (default) or 1.7.") do |value|
        supported = StillActive::CyclonedxHelper::SUPPORTED_SPEC_VERSIONS
        raise ArgumentError, "--cyclonedx-version must be one of: #{supported.join(", ")} (got #{value})" unless supported.include?(value)

        options[:provided_cyclonedx_version] = true
        StillActive.config { |config| config.cyclonedx_version = value }
      end
    end

    def add_token_options(opts)
      opts.on("--github-oauth-token=TOKEN", String, "GitHub OAuth token to make API calls") do |value|
        StillActive.config { |config| config.github_oauth_token = value }
      end
      opts.on("--gitlab-token=TOKEN", String, "GitLab personal access token for API calls") do |value|
        StillActive.config { |config| config.gitlab_token = value }
      end
      opts.on("--ecosystems-email=EMAIL", String, "Contact email for the ecosyste.ms polite pool (used only when falling back to ecosyste.ms without a GitHub token)") do |value|
        email = value.strip
        warn("warning: --ecosystems-email=#{value.inspect} doesn't look like an email (no @); ecosyste.ms will keep you in the anonymous pool") unless email.include?("@")
        StillActive.config { |config| config.ecosystems_email = email }
      end
      opts.on("--artifactory-token=TOKEN", String, "Artifactory token for private gem registry API calls") do |value|
        StillActive.config { |config| config.artifactory_token = value }
      end
      opts.on("--artifactory-host=HOST", String, "Artifactory host that may receive the global token (e.g. my-org.jfrog.io)") do |value|
        StillActive.config { |config| config.artifactory_host = value }
      end
    end

    def add_parallelism_options(opts)
      opts.on("--simultaneous-requests=QTY", Integer, "Number of simultaneous requests made") do |value|
        StillActive.config { |config| config.parallelism = value }
      end
    end

    def add_range_options(opts)
      opts.on(
        "--safe-range-end=YEARS",
        Float,
        "maximum years since last release considered safe, no warning (default 1.5; fractional allowed)",
      ) do |value|
        StillActive.config { |config| config.no_warning_range_end = value }
      end
      opts.on(
        "--warning-range-end=YEARS",
        Float,
        "maximum years since last release that triggers a warning, beyond this is critical (default 3)",
      ) do |value|
        StillActive.config { |config| config.warning_range_end = value }
      end
    end

    def add_exit_options(opts)
      opts.on("--fail-if-critical", "Exit 1 if any gem has critical activity warning") do
        StillActive.config { |config| config.fail_if_critical = true }
      end
      opts.on("--fail-if-warning", "Exit 1 if any gem has warning or critical activity warning") do
        StillActive.config { |config| config.fail_if_warning = true }
      end
      opts.on("--fail-if-vulnerable[=SEVERITY]", "Exit 1 if any gem has vulnerabilities (optionally at or above SEVERITY: low, medium, high, critical)") do |value|
        if value
          valid = VulnerabilityHelper::SEVERITY_ORDER
          raise ArgumentError, "--fail-if-vulnerable severity must be one of: #{valid.join(", ")} (got #{value})" unless valid.include?(value)

          StillActive.config { |config| config.fail_if_vulnerable = value }
        else
          StillActive.config { |config| config.fail_if_vulnerable = true }
        end
      end
      opts.on("--fail-if-outdated=LIBYEARS", Float, "Exit 1 if any gem exceeds LIBYEARS behind latest") do |value|
        StillActive.config { |config| config.fail_if_outdated = value }
      end
      opts.on("--fail-if-poison[=TIER]", "Exit 1 on a poison-pill at or above TIER (note|warning|critical; default warning)") do |value|
        if value
          valid = StillActive::ConstraintHelper::SEVERITY.map(&:to_s)
          raise ArgumentError, "--fail-if-poison tier must be one of: #{valid.join(", ")} (got #{value})" unless valid.include?(value)

          StillActive.config { |config| config.fail_if_poison = value.to_sym }
        else
          StillActive.config { |config| config.fail_if_poison = true }
        end
      end
      opts.on("--fail-if-language-ceiling[=TIER]", "Exit 1 on a language-runtime ceiling (Ruby/Python; default: EOL-forced only; =note also gates latest-not-yet)") do |value|
        if value
          valid = StillActive::ConstraintHelper::SEVERITY.map(&:to_s)
          raise ArgumentError, "--fail-if-language-ceiling tier must be one of: #{valid.join(", ")} (got #{value})" unless valid.include?(value)

          # Ceiling findings are only ever :critical or :note, so =warning can't
          # match anything the bare (=critical) default doesn't already catch.
          if value == "warning"
            $stderr.puts("warning: --fail-if-language-ceiling=warning has no effect (runtime ceilings are only critical or note); behaves as =critical")
          end
          StillActive.config { |config| config.fail_if_language_ceiling = value.to_sym }
        else
          StillActive.config { |config| config.fail_if_language_ceiling = true }
        end
      end
    end

    def add_emoji_options(opts)
      opts.on("--critical-warning-emoji=EMOJI") { |value| StillActive.config { |config| config.critical_warning_emoji = value } }
      opts.on("--futurist-emoji=EMOJI") { |value| StillActive.config { |config| config.futurist_emoji = value } }
      opts.on("--success-emoji=EMOJI") { |value| StillActive.config { |config| config.success_emoji = value } }
      opts.on("--unsure-emoji=EMOJI") { |value| StillActive.config { |config| config.unsure_emoji = value } }
      opts.on("--warning-emoji=EMOJI") { |value| StillActive.config { |config| config.warning_emoji = value } }
    end

    def add_banner(opts)
      opts.banner = <<-BANNER.gsub(/\A\s{8}/, "")
        Usage: #{opts.program_name} [options]

        all flags are optional

      BANNER
    end

    def add_tail_options(opts)
      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end
      opts.on_tail("-v", "--version", "Show version") do
        puts StillActive::VERSION
        exit
      end
    end
  end
end
