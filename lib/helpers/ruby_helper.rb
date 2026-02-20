# frozen_string_literal: true

require "time"
require_relative "http_helper"
require_relative "libyear_helper"

module StillActive
  module RubyHelper
    extend self

    ENDOFLIFE_URI = URI("https://endoflife.date/")

    def ruby_freshness
      return unless standard_ruby?

      cycles = fetch_cycles
      return if cycles.nil?

      current = current_ruby_version
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

    private

    def standard_ruby?
      RUBY_ENGINE == "ruby"
    end

    def current_ruby_version
      RUBY_VERSION
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
