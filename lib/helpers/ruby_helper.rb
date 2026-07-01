# frozen_string_literal: true

require "time"
require_relative "bundler_helper"
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
      latest_release_date = parse_date(latest_cycle["releaseDate"])
      current_release_date = parse_date(current_cycle&.dig("releaseDate"))
      eol_value = current_cycle&.dig("eol")

      {
        version: current,
        release_date: current_release_date,
        eol_date: parse_eol(eol_value),
        eol: eol_reached?(eol_value),
        latest_version: latest_version,
        latest_release_date: latest_release_date,
        libyear: LibyearHelper.gem_libyear(
          version_used_release_date: current_release_date,
          latest_version_release_date: latest_release_date,
        ),
      }
    end

    # The runtime facts a per-gem language ceiling is measured against: the
    # oldest Ruby cycle still receiving security releases, the latest stable
    # release, and the normalized cycle list (version + EOL flag/date) so a
    # ceiling finding can name the exact Ruby a cap strands you on and how long
    # it's been dead. Reuses the same endoflife.date feed as #ruby_freshness.
    # Returns nil when the feed is unavailable or every known cycle is EOL (no
    # supported floor to compare against).
    def supported_ruby_range
      cycles = fetch_cycles
      return if cycles.nil? || cycles.empty?

      # endoflife.date is best-effort third-party data. Guard the newest cycle's
      # `latest` the same way normalize_cycle guards `cycle`: a malformed/preview
      # value must degrade to "sit out" (nil), not raise. This method is fetched
      # once outside the per-gem rescue, so an unguarded raise would abort the
      # entire audit, contrary to the best-effort contract.
      latest = cycles.first["latest"]
      return unless latest && Gem::Version.correct?(latest)

      normalized = cycles.filter_map { |cycle| normalize_cycle(cycle) }
      supported = normalized.reject { |cycle| cycle[:eol] }
      return if supported.empty?

      {
        oldest_supported: supported.map { |cycle| cycle[:version] }.min,
        latest_stable: Gem::Version.new(latest),
        cycles: normalized,
      }
    end

    private

    def normalize_cycle(cycle)
      version = cycle["cycle"]
      return unless version && Gem::Version.correct?(version)

      {
        version: Gem::Version.new(version),
        eol: eol_reached?(cycle["eol"]) == true,
        eol_date: parse_eol(cycle["eol"]),
      }
    end

    def current_ruby_version
      lockfile_ruby_version || (RUBY_ENGINE == "ruby" ? RUBY_VERSION : nil)
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

    def parse_date(date_string)
      return if date_string.nil?

      Time.parse(date_string)
    end

    def parse_eol(value)
      case value
      when String then parse_date(value)
      end
    end

    def eol_reached?(value)
      case value
      when true then true
      when false then false
      when String then Time.parse(value) <= Time.now
      end
    end
  end
end
