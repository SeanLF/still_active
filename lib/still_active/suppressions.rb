# frozen_string_literal: true

require "date"

module StillActive
  # Granular, auditable suppression of individual findings, loaded from the
  # `ignore:` block of a committed .still_active.yml. Each entry silences one
  # signal (activity / vulnerability / libyear / poison) or one advisory for one
  # gem, optionally until an expiry date, replacing the all-or-nothing whole-gem
  # --ignore. A bare gem
  # name (or a gem-only mapping) keeps the old whole-gem behaviour so --ignore
  # can union into the same list.
  #
  # Two guardrails keep suppression from hiding live risk: a lapsed entry stops
  # applying so the finding re-surfaces, and a vulnerability suppression must
  # name an explicit advisory id, so a newly disclosed CVE on the same gem is
  # never pre-silenced.
  class Suppressions
    GATEABLE_SIGNALS = [:activity, :vulnerability, :libyear, :poison].freeze

    Entry = Struct.new(:gem, :advisory, :signal, :reason, :expires, keyword_init: true) do
      def whole_gem?
        signal.nil? && advisory.nil?
      end

      def expired?(today)
        !expires.nil? && expires < today
      end

      def covers?(signal:, advisory:, aliases:)
        return true if whole_gem?

        if self.signal == :vulnerability
          [advisory, *aliases].compact.include?(self.advisory)
        else
          self.signal == signal
        end
      end
    end

    class << self
      def from(raw, today: Date.today)
        warnings = []
        entries = Array(raw).filter_map { |item| parse_entry(item, warnings) }
        new(entries, warnings, today)
      end

      private

      def parse_entry(item, warnings)
        return Entry.new(gem: item, advisory: nil, signal: nil, reason: nil, expires: nil) if item.is_a?(String)

        unless item.is_a?(Hash)
          warnings << "ignoring suppression entry #{item.inspect}: expected a gem name or a mapping"
          return
        end

        gem = item["gem"]
        advisory = item["advisory"]
        signal = item["signal"]&.to_sym
        signal ||= :vulnerability if advisory
        expires = parse_expires(item["expires"], item, warnings)
        return if expires == :invalid

        label = gem || advisory || "entry"
        return unless valid?(gem:, advisory:, signal:, label:, warnings:)

        Entry.new(gem:, advisory:, signal:, reason: item["reason"], expires:)
      end

      # Returns true when the entry is well-formed, otherwise records a warning
      # and returns false so the caller skips (does not apply) the entry.
      def valid?(gem:, advisory:, signal:, label:, warnings:)
        if gem.nil? && signal.nil? && advisory.nil?
          warnings << "ignoring suppression entry: needs a gem, signal, or advisory"
          return false
        end
        if signal && !GATEABLE_SIGNALS.include?(signal)
          warnings << "ignoring suppression for #{label}: unknown signal #{signal.inspect} (expected activity, vulnerability, libyear, or poison)"
          return false
        end
        if signal == :vulnerability && advisory.nil?
          warnings << "ignoring vulnerability suppression for #{label}: must name an advisory id so newly disclosed advisories still surface"
          return false
        end
        if [:activity, :libyear, :poison].include?(signal) && gem.nil?
          warnings << "ignoring #{signal} suppression: must name a gem"
          return false
        end

        true
      end

      def parse_expires(value, item, warnings)
        return if value.nil?
        return value if value.is_a?(Date)

        Date.parse(value.to_s)
      rescue ArgumentError, TypeError
        warnings << "ignoring suppression #{item.inspect}: unparseable expires #{value.inspect}"
        :invalid
      end
    end

    attr_reader :warnings

    def initialize(entries, warnings, today)
      @entries = entries
      @warnings = warnings
      @today = today
    end

    def suppressed?(gem:, signal:, advisory: nil, aliases: [])
      !match(gem:, signal:, advisory:, aliases:).nil?
    end

    # Warnings for live entries that name a gem absent from the audited set: they
    # can never match, so they are dead config (a typo, or a gem removed since
    # the suppression was written). This is the presence axis of suppression rot;
    # `expired?` already covers the time axis, so an expired entry isn't
    # re-reported here, and a gem-agnostic advisory entry (gem nil) is skipped
    # since it applies across the whole graph.
    def stale_gem_warnings(present_gems)
      @entries.filter_map do |entry|
        next if entry.expired?(@today)
        next unless entry.gem && !present_gems.include?(entry.gem)

        "suppression for #{entry.gem} never applies: it is not in the audited dependencies (typo, or removed since it was suppressed?)"
      end
    end

    # The first live entry covering this finding, or nil. Used by SARIF to carry
    # the suppression's reason as the native suppressions[] justification.
    def match(gem:, signal:, advisory: nil, aliases: [])
      @entries.find do |entry|
        next false if entry.expired?(@today)
        next false unless entry.gem.nil? || entry.gem == gem

        entry.covers?(signal:, advisory:, aliases:)
      end
    end
  end
end
