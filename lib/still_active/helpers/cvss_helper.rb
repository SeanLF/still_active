# frozen_string_literal: true

module StillActive
  # Computes a CVSS score from a vector string, across v2/v3/v4. deps.dev stores only
  # CVSS 3.x, so a CVSS-4-only advisory (the flagship protobuf case) arrives with no
  # numeric score; OSV carries the v4 vector, and this turns it into the number the
  # SARIF security-severity and CycloneDX rating want.
  #
  # cvss-suite is an OPTIONAL, undeclared dependency: it over-constrains its own deps
  # (an exact `bundler` pin, a `bigdecimal ~> 3.1` cap), the poison-pill pattern
  # still_active itself flags, so hard-requiring it would force that liability on every
  # user and trip our own audit. CvssHelper soft-requires it; install cvss-suite (or run
  # the distribution that bundles it) to light it up.
  #
  # Returns cvss-suite's `overall_score`: for the base-only vectors OSV publishes that
  # IS the base score, but a vector carrying threat/environmental metrics would fold
  # those in -- which is why the severity band floors at the authoritative GHSA label
  # (VulnerabilityHelper.advisory_severity) and this number never lowers it: the label
  # drives gating and SARIF level, the number only sharpens display. Fails safe: an
  # absent gem or an absent/unparseable vector yields nil, never a crash.
  module CvssHelper
    extend self

    def score(vector)
      return unless available?
      return if vector.nil? || vector.to_s.empty?

      cvss = CvssSuite.new(vector.to_s)
      cvss.valid? ? cvss.overall_score : nil
    rescue => e
      # We only reach here with cvss-suite loaded (available?), so a raise is the
      # installed gem failing this call site -- an incompatible version, a renamed
      # `overall_score` -- not a bad vector, which cvss-suite reports via valid?.
      # Fail safe to nil (the number is display-only, never gates), but don't
      # swallow it: an opted-in-but-broken scorer that emitted nothing would read
      # as "no advisories are scored". Warn once per run (not per advisory),
      # matching OsvClient.enrich rather than staying silent.
      warn_scorer_failed(e)
      nil
    end

    # Memoized soft-require: true once cvss-suite loads, false when it isn't installed.
    def available?
      return @available unless @available.nil?

      @available = begin
        require "cvss_suite"
        true
      rescue LoadError
        false
      end
    end

    private

    def warn_scorer_failed(error)
      return if @warned

      @warned = true
      warn("warning: cvss-suite scoring failed: #{error.class} (#{error.message}); CVSS numbers unavailable this run, check your cvss-suite version")
    end
  end
end
