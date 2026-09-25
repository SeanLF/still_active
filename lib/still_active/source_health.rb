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
  # freshness canary asks, per ecosystem in the audit, for packages that publish
  # often and expects one of them to have published in the last 30 days: a stalled index
  # serves stale versions and misses new advisories without any error. Neither
  # catches one stale package in a live index (deps.dev's Go stdlib was that).
  module SourceHealth
    extend self

    # Packages that publish often; an ecosystem is fresh if ANY of its set has a
    # version published in the window. Chosen by replaying two years of deps.dev
    # publish dates (2026-09-24): the longest stretch with no version from the
    # set is 10 days (nuget), 8.7 (npm), 7 (cargo, rubygems), 6.7 (pypi, maven),
    # 6 (go), so 30 days is a 3x margin. Single canaries weren't enough:
    # aws-sdk-core went 34 days and golang.org/x/net 35, which would have failed
    # a healthy index closed. Recheck with each set's publishedAt history.
    FRESHNESS_CANARIES = {
      rubygems: ["aws-partitions", "aws-sdk-ec2"],
      npm: ["next", "@types/node"],
      pypi: ["boto3", "botocore"],
      cargo: ["aws-sdk-ec2", "oxc_parser", "swc_core"],
      go: ["cloud.google.com/go/storage", "github.com/aws/aws-sdk-go-v2/service/s3"],
      maven: ["software.amazon.awssdk:s3", "software.amazon.awssdk:ec2"],
      nuget: ["AWSSDK.S3", "AWSSDK.Core"]
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
        lines << "deps.dev's advisory check failed (its `advisoryKeys` field may have changed, or the API is unreachable); its advisories count as unchecked unless another source answers for them (ruby-advisory-db, OSV for the Go toolchain)" unless advisory_schema_ok
        stale_ecosystems.each do |ecosystem|
          lines << "deps.dev's #{ecosystem} index has nothing published by #{FRESHNESS_CANARIES[ecosystem].join(", ")} in 30 days (or couldn't be read), so it looks stale; its #{ecosystem} advisories count as unchecked unless another source answers for them, and its latest versions may be behind"
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

    # Fresh when any canary has a version published in the window. One that can't
    # be read (after the client's retry) just doesn't count; if none can, the check
    # can't confirm freshness and reads stale.
    def fresh?(ecosystem, now)
      FRESHNESS_CANARIES[ecosystem].any? do |name|
        date = DepsDevClient.newest_publish_date(name: name, system: ecosystem)
        !date.nil? && now - Time.parse(date) < FRESH_WITHIN_SECONDS
      rescue HttpHelper::Unavailable, ArgumentError, TypeError
        false
      end
    end
  end
end
