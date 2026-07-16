# frozen_string_literal: true

require "time"
require_relative "bundler_helper"
require_relative "endoflife_helper"
require_relative "http_helper"
require_relative "libyear_helper"

module StillActive
  module RubyHelper
    extend self

    ENDOFLIFE_URI = URI("https://endoflife.date/")

    def ruby_freshness
      current = current_ruby_version
      return if current.nil?

      cycles = fetch_cycles
      return if cycles.nil?

      current_cycle = find_cycle(cycles, current)
      latest_cycle = cycles.first

      return if latest_cycle.nil?

      latest_version = latest_cycle["latest"]
      latest_release_date = EndoflifeHelper.parse_date(latest_cycle["releaseDate"])
      current_release_date = EndoflifeHelper.parse_date(current_cycle&.dig("releaseDate"))
      eol_value = current_cycle&.dig("eol")

      {
        version: current,
        release_date: current_release_date,
        eol_date: EndoflifeHelper.parse_eol(eol_value),
        eol: EndoflifeHelper.eol_reached?(eol_value),
        latest_version: latest_version,
        latest_release_date: latest_release_date,
        libyear: LibyearHelper.gem_libyear(
          version_used_release_date: current_release_date,
          latest_version_release_date: latest_release_date
        )
      }
    end

    # The runtime facts a per-gem language ceiling is measured against, sourced
    # from the shared endoflife.date support-window builder. Ruby only picks the
    # feed; the ecosystem-neutral logic (support floor, latest stable, grace
    # window, cycle normalization) lives in EndoflifeHelper.
    def supported_ruby_range
      EndoflifeHelper.support_window(feed_path: "/api/ruby.json")
    end

    private

    def current_ruby_version
      lockfile_ruby_version || ((RUBY_ENGINE == "ruby") ? RUBY_VERSION : nil)
    end

    def lockfile_ruby_version
      # Use the configured gemfile (honours --gemfile) rather than the ambient
      # BUNDLE_GEMFILE, which only happened to work when BundlerHelper set it as
      # a side-effect. Refs #42.
      lockfile_path = BundlerHelper.lockfile_path_for(File.expand_path(StillActive.config.gemfile_path))
      return unless File.exist?(lockfile_path)

      content = File.read(lockfile_path)
      match = content.match(/^RUBY VERSION\n\s+ruby (\d+\.\d+\.\d+)/)
      match&.[](1)
    end

    def fetch_cycles
      HttpHelper.get_json(ENDOFLIFE_URI, "/api/ruby.json")
    end

    def find_cycle(cycles, version)
      major_minor = version.split(".")[0..1].join(".")
      cycles.find { |c| c["cycle"] == major_minor }
    end
  end
end
