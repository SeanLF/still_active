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
        add_output_options(opts)
        add_token_options(opts)
        add_parallelism_options(opts)
        add_range_options(opts)
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

    def add_output_options(opts)
      opts.on("--markdown", "Prints output in markdown format") { StillActive.config { |config| config.output_format = :markdown } }
      opts.on("--json", "Prints output in JSON format") { StillActive.config { |config| config.output_format = :json } }
    end

    def add_token_options(opts)
      opts.on("--github-oauth-token=TOKEN", String, "GitHub OAuth token to make API calls") do |value|
        StillActive.config { |config| config.github_oauth_token = value }
      end
    end

    def add_parallelism_options(opts)
      opts.on("--simultaneous-requests=QTY", Integer, "Number of simultaneous requests made") do |value|
        StillActive.config { |config| config.simultaneous_request_quantity = value }
      end
    end

    def add_range_options(opts)
      opts.on("--safe-range-end=YEARS", Integer,
        "maximum number of years since last activity to be considered safe") do |value|
        StillActive.config { |config| config.safe_range_end = value }
      end
      opts.on("--warning-range-end=YEARS", Integer,
        "maximum number of years since last activity to be considered worrying") do |value|
        StillActive.config { |config| config.warning_range_end = value }
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
