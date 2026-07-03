# frozen_string_literal: true

require "cvss_suite"

module StillActive
  # Computes a CVSS score from a vector string, across v2/v3/v4. deps.dev stores only
  # CVSS 3.x, so a CVSS-4-only advisory (the flagship protobuf case) arrives with no
  # numeric score; OSV carries the v4 vector, and this turns it into the number the
  # SARIF security-severity and CycloneDX rating need. Returns cvss-suite's
  # `overall_score`: for the base-only vectors OSV publishes that IS the base score,
  # but a vector carrying threat/environmental metrics would fold those in -- which is
  # why the severity BAND (VulnerabilityHelper.advisory_severity) floors at the
  # authoritative GHSA label and this number never lowers it. Fails safe: it feeds a
  # display field and must never crash the audit, so an absent/unparseable vector
  # yields nil.
  module CvssHelper
    extend self

    def score(vector)
      return if vector.nil? || vector.to_s.empty?

      cvss = CvssSuite.new(vector.to_s)
      cvss.valid? ? cvss.overall_score : nil
    rescue StandardError
      nil
    end
  end
end
