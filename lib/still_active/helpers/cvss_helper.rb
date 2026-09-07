# frozen_string_literal: true

require "cvss_suite"

module StillActive
  # Computes a CVSS base score from a vector string, across v2/v3/v4. deps.dev stores
  # only CVSS 3.x, so a CVSS-4-only advisory (the flagship protobuf case) arrives with
  # no numeric score; OSV carries the v4 vector, and this turns it into the number the
  # SARIF security-severity and CycloneDX rating want.
  #
  # Returns the BASE score, not cvss-suite's overall_score: a vector carrying threat or
  # environmental metrics folds those into overall_score (E:U alone turns a 9.3 into
  # an 8.1), while NVD and GHSA publish the base score. The severity band still floors
  # at the authoritative GHSA label (VulnerabilityHelper.advisory_severity) because
  # labels are assigned by people and can sit off the FIRST band edge; the label drives
  # gating and SARIF level, the number sharpens display. Fails safe: an absent or
  # unparseable vector yields nil, never a crash.
  module CvssHelper
    extend self

    def score(vector)
      return if vector.nil? || vector.to_s.empty?

      CvssSuite.parse(vector.to_s).base_score
    rescue CvssSuite::Error
      nil
    end
  end
end
