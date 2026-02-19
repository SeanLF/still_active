# frozen_string_literal: true

require "optparse"

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
      raise ArgumentError, "provide gemfile or gems, not both" if options[:provided_gemfile] && options[:provided_gems]
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
        StillActive.config { |config| config.gems = value }
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
    end

    def add_token_options(opts)
      opts.on("--github-oauth-token=TOKEN", String, "GitHub OAuth token to make API calls") do |value|
        StillActive.config { |config| config.github_oauth_token = value }
      end
      opts.on("--gitlab-token=TOKEN", String, "GitLab personal access token for API calls") do |value|
        StillActive.config { |config| config.gitlab_token = value }
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
        Integer,
        "maximum years since last activity considered safe (no warning)",
      ) do |value|
        StillActive.config { |config| config.no_warning_range_end = value }
      end
      opts.on(
        "--warning-range-end=YEARS",
        Integer,
        "maximum years since last activity that triggers a warning (beyond this is critical)",
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
      opts.on("--fail-below-score=SCORE", Integer, "Exit 1 if any gem's health score is below SCORE (0-100)") do |value|
        StillActive.config { |config| config.fail_below_score = value }
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
