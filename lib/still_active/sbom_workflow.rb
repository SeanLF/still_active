# frozen_string_literal: true

require_relative "ecosystem_lens"
require "async"
require "async/barrier"
require "async/semaphore"

module StillActive
  # The SBOM audit's fan-out, parallel to Workflow but for a cross-ecosystem
  # SBOM rather than a Bundler lockfile: it runs EcosystemLens over each
  # dependency concurrently and returns a result hash the same output path can
  # render. Keyed by "ecosystem/name@version" (not bare name) so nothing collides
  # and overwrites: not an npm `foo` against a pypi `foo`, and -- the case a merged
  # monorepo SBOM actually produces -- not two versions of the same package pinned
  # by different subprojects (a lockfile resolves one version per name, an SBOM
  # doesn't). Each is a distinct assessable unit with its own version-specific
  # advisory set, so collapsing them would silently drop one dep's verdict.
  module SbomWorkflow
    extend self

    # `assessed` is the "ecosystem/name@version" => gem_data hash; `failures` is
    # the deps whose lens call raised (a rate-limited/flaky deps.dev, or a bug
    # hitting every dep). The two are returned separately so run_sbom can surface
    # the failures instead of dropping them: a raised dep that just vanished would
    # be absent from the JSON, uncounted, and past the exit gate, letting a
    # rate-limited run read "all clear" while silently skipping deps.
    Outcome = Data.define(:assessed, :failures)

    def call(sbom_result, &on_progress)
      dependencies = sbom_result.dependencies
      Async do
        barrier = Async::Barrier.new
        semaphore = Async::Semaphore.new(StillActive.config.parallelism, parent: barrier)
        result = {}
        failures = []
        total = dependencies.size
        completed = 0
        dependencies.each do |dep|
          semaphore.async do
            result["#{dep[:ecosystem]}/#{dep[:name]}@#{dep[:version]}"] =
              EcosystemLens.assess(ecosystem: dep[:ecosystem], name: dep[:name], version: dep[:version])
          rescue StandardError => e
            # One dependency's failure must not abort the audit, but it must not
            # disappear either: record it as an unassessable entry (same shape as
            # the reader's, with a distinct reason) so it's counted and reported.
            failures << { ecosystem: dep[:ecosystem], name: dep[:name], version: dep[:version], reason: :assessment_error, error: "#{e.class}: #{e.message}" }
            $stderr.puts("error assessing #{dep[:ecosystem]}/#{dep[:name]}@#{dep[:version]}: #{e.class}\n\t#{e.message}")
          ensure
            completed += 1
            on_progress&.call(completed, total)
          end
        end
        barrier.wait
        # Stable, diffable order regardless of async completion order.
        Outcome.new(
          assessed: result.sort_by { |key, _| key }.to_h,
          failures: failures.sort_by { |failure| "#{failure[:ecosystem]}/#{failure[:name]}@#{failure[:version]}" },
        )
      end.wait
    end
  end
end
