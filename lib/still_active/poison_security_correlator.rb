# frozen_string_literal: true

require_relative "../helpers/vulnerability_helper"

module StillActive
  # Whole-tree correlation, run once after the fan-out: a poison cap is far more
  # urgent when the dependency it pins is ITSELF vulnerable in the same tree --
  # "a dormant package is holding you on a known-vulnerable dependency, below the
  # version that fixes it." Both facts are already assembled (the poison
  # constraints and every dependency's vulnerability count), so this is one pass,
  # no extra fetches. It marks the security-relevant caps so the report can lead
  # with them and demote the FYI caps on healthy dependencies.
  #
  # The moat's strongest case (verified on real repos): several archived Google
  # client libraries pin a vulnerable `protobuf` three majors below the fix.
  module PoisonSecurityCorrelator
    extend self

    # Only a HIGH-or-above advisory on the capped dep makes the cap security-
    # relevant. Most advisories are low-threat noise (research: ~95% of vulnerable
    # deps are unreachable/low-impact), so a low/medium CVE on the pinned dep isn't
    # the "you're stuck below the fix" story. Unscored advisories fail CLOSED (a
    # confirmed advisory we can't score could be severe), matching --fail-if-
    # vulnerable. Reachability/exploitability is beyond static, metadata-only sight
    # and deliberately out of scope -- this gates on severity, not exploitability.
    SECURITY_THRESHOLD = "high"

    def correlate(result_object)
      # Ecosystem-qualified map of each tree package's advisories. A capped dep
      # resolves in its capper's ecosystem, so match "ecosystem/name" on both
      # sides; native results carry no :ecosystem (nil on both) and still match.
      advisories = result_object.each_with_object({}) do |(key, data), map|
        next unless data[:vulnerability_count].to_i.positive?

        name = data[:name] || key
        map["#{data[:ecosystem]}/#{name}"] = data[:vulnerabilities] || []
      end

      result_object.each_value do |data|
        constraints = data[:constraints]
        next if constraints.nil? || constraints.empty?

        eco = data[:ecosystem]
        constraints.each do |constraint|
          vulns = advisories["#{eco}/#{constraint[:dependency]}"]
          next if vulns.nil?

          constraint[:capped_dep_vulnerable] = true if VulnerabilityHelper.severity_at_or_above?(vulns, SECURITY_THRESHOLD)
        end
        data[:poison_security_relevant] = true if constraints.any? { |c| c[:capped_dep_vulnerable] }
      end
    end
  end
end
