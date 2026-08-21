# frozen_string_literal: true

require "time"
require_relative "http_helper"

module StillActive
  # The ecosystem-neutral support-window builder over an endoflife.date feed.
  # Given a feed path (`/api/ruby.json`, `/api/python.json`, ...) it returns the
  # runtime facts a per-package language ceiling is measured against: the oldest
  # cycle still receiving security releases, the latest stable release, a
  # grace-window flag, and the normalized cycle list. RubyHelper and PythonHelper
  # are thin calibration wrappers that only choose the feed path, exactly as
  # RuntimeCeilingHelper keeps the ceiling math generic and pushes the runtime
  # specifics to the edges. RubyHelper#ruby_freshness also reuses the cycle-date
  # parsing here so there is one home for reading this best-effort feed.
  #
  # Everything degrades on bad third-party data rather than raising: the window is
  # fetched once outside the per-package rescue, so an unguarded raise would abort
  # the whole audit. A single malformed field must cost at most the finding it
  # feeds, never the whole signal.
  module EndoflifeHelper
    extend self

    ENDOFLIFE_URI = URI("https://endoflife.date/")

    # How long a newly-released runtime gets before packages are held accountable
    # for not yet declaring support for it. Below this, a latest-not-yet ceiling
    # is about the release calendar, not the package, so the note is suppressed.
    LATEST_STABLE_GRACE_SECONDS = 90 * 24 * 60 * 60

    # => { oldest_supported:, latest_stable:, latest_stable_fresh:, cycles: } of
    # Gem::Versions plus normalized EOL cycles, or nil when the feed is
    # unavailable, empty, or every known cycle is EOL (no supported floor to
    # compare against). `latest_stable` is nil when the newest cycle's `latest` is
    # malformed -- see below.
    def support_window(feed_path:)
      cycles = fetch_cycles(feed_path)
      return if cycles.nil? || cycles.empty?

      normalized = cycles.filter_map { |cycle| normalize_cycle(cycle) }
      supported = normalized.reject { |cycle| cycle[:eol] }
      return if supported.empty?

      # A malformed/preview `latest` on the newest cycle must not sink the whole
      # window: latest_stable feeds only the latest-not-yet NOTE, whereas the
      # EOL-forced CRITICAL depends solely on the cycles' eol flags. Degrade it to
      # nil (the note is then suppressed) rather than returning nil, which would
      # silently disable criticals too.
      latest = cycles.first["latest"]
      latest_stable = (latest && Gem::Version.correct?(latest)) ? Gem::Version.new(latest) : nil

      {
        oldest_supported: supported.map { |cycle| cycle[:version] }.min,
        latest_stable: latest_stable,
        latest_stable_fresh: !latest_stable.nil? && latest_stable_fresh?(cycles.first),
        cycles: normalized
      }
    end

    # A best-effort date parse over this feed's values: nil for a missing OR
    # malformed date, never a raise. endoflife.date is third-party data; a garbled
    # date on one cycle must degrade that cycle, not abort the run.
    def parse_date(date_string)
      return if date_string.nil?

      Time.parse(date_string)
    rescue ArgumentError
      nil
    end

    def parse_eol(value)
      case value
      when String then parse_date(value)
      end
    end

    # true / false when the eol date is known, nil when it's absent or malformed
    # (so callers can decide how to treat "unknown"). Routes through parse_date, so
    # a garbled eol string degrades to nil rather than raising.
    def eol_reached?(value)
      case value
      when true then true
      when false then false
      when String
        parsed = parse_date(value)
        parsed.nil? ? nil : parsed <= Time.now
      end
    end

    private

    def fetch_cycles(feed_path)
      HttpHelper.get_json(ENDOFLIFE_URI, feed_path)
    end

    def normalize_cycle(cycle)
      version = cycle["cycle"]
      return unless version && Gem::Version.correct?(version)

      {
        version: Gem::Version.new(version),
        eol: eol_reached?(cycle["eol"]) == true,
        eol_date: parse_eol(cycle["eol"])
      }
    end

    def latest_stable_fresh?(latest_cycle)
      released = parse_date(latest_cycle["releaseDate"])
      return false if released.nil?

      (Time.now - released) < LATEST_STABLE_GRACE_SECONDS
    end
  end
end
