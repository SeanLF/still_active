# frozen_string_literal: true

require "time"
require_relative "deps_dev_client"

module StillActive
  # Whether deps.dev is answering in the shape we read and is current, checked once
  # per run before the fan-out. deps.dev is an alpha API and it is the advisory
  # source for everything but ruby-advisory-db and the Go toolchain, so when it
  # isn't healthy its advisories count as unchecked rather than clean.
  #
  # Two checks. The advisory canary asks for a package with permanent advisories
  # and expects them back (a renamed field reads as zero everywhere). The
  # freshness canary asks, per ecosystem in the audit, for a package that ships
  # every few days and expects a release in the last 30 days: a stalled index
  # serves stale versions and misses new advisories without any error. Neither
  # catches one stale package in a live index (deps.dev's Go stdlib was that).
  module SourceHealth
    extend self

    # Publishers that release every few days (each verified under 10 days old on
    # 2026-09-24), so 30 days without a release means the index stalled.
    FRESHNESS_CANARIES = {
      rubygems: "aws-sdk-core",
      npm: "@types/node",
      pypi: "boto3",
      cargo: "aws-sdk-s3",
      go: "golang.org/x/net",
      maven: "software.amazon.awssdk:s3",
      nuget: "AWSSDK.Core"
    }.freeze
    FRESH_WITHIN_SECONDS = 30 * 24 * 60 * 60

    Report = Data.define(:advisory_schema_ok, :stale_ecosystems) do
      def self.healthy = new(advisory_schema_ok: true, stale_ecosystems: [])

      # Whether deps.dev's advisories for this ecosystem count as an answer.
      def deps_dev_trusted?(ecosystem)
        advisory_schema_ok && !stale_ecosystems.include?(ecosystem)
      end

      def degraded? = !advisory_schema_ok || !stale_ecosystems.empty?

      def as_json
        {
          status: degraded? ? "degraded" : "ok",
          deps_dev_advisories: advisory_schema_ok ? "ok" : "failed",
          deps_dev_stale_ecosystems: stale_ecosystems.map(&:to_s)
        }
      end

      def warnings
        lines = []
        lines << "deps.dev's advisory check failed (its `advisoryKeys` field may have changed, or the API is unreachable); advisories from it are treated as unchecked" unless advisory_schema_ok
        stale_ecosystems.each do |ecosystem|
          lines << "deps.dev's #{ecosystem} index has no release of #{FRESHNESS_CANARIES[ecosystem]} in 30 days (or couldn't be read), so it looks stale; #{ecosystem} advisories from it are treated as unchecked and its latest versions may be behind"
        end
        lines
      end
    end

    def check(ecosystems:, now: Time.now)
      Report.new(
        advisory_schema_ok: DepsDevClient.advisory_schema_ok?,
        stale_ecosystems: ecosystems.uniq.select { FRESHNESS_CANARIES.key?(_1) && !fresh?(_1, now) }
      )
    end

    private

    # Unreachable or unreadable counts as not fresh: the check can't confirm it.
    def fresh?(ecosystem, now)
      date = DepsDevClient.latest_release_date(name: FRESHNESS_CANARIES[ecosystem], system: ecosystem)
      !date.nil? && now - Time.parse(date) < FRESH_WITHIN_SECONDS
    rescue ArgumentError, TypeError
      false
    end
  end
end
