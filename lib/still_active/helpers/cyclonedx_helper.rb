# frozen_string_literal: true

require "json"
require "digest"
require "time"
require_relative "status_helper"
require_relative "vulnerability_helper"

module StillActive
  # Renders a still_active workflow result as a CycloneDX SBOM. Emits 1.6 by
  # default (the version mainstream consumers — Dependency-Track via
  # cyclonedx-core-java, Trivy/Syft via cyclonedx-go — actually ingest as of
  # 2026); 1.7 is opt-in. Our emitted subset is identical across both versions,
  # so only the specVersion string changes.
  #
  # Maintenance signals that have no native CycloneDX field (scorecard, libyear,
  # archived, last commit) are emitted as `still_active:`-namespaced component
  # properties — lossy by spec design, ignorable by consumers that don't care.
  module CyclonedxHelper
    extend self

    SUPPORTED_SPEC_VERSIONS = ["1.6", "1.7"].freeze

    # result: gem_name => gem_data (as StillActive::Workflow.call returns)
    # ruby_info: Ruby freshness hash or nil
    # now: injectable clock so output is deterministic in tests
    def render(result:, ruby_info:, tool_version:, spec_version: "1.6", now: Time.now.utc)
      components = build_components(result, ruby_info)
      vulnerabilities = build_vulnerabilities(result)

      document = envelope(components, spec_version, tool_version, now)
      document["vulnerabilities"] = vulnerabilities unless vulnerabilities.empty?
      JSON.pretty_generate(document)
    end

    # The cross-ecosystem sibling of `render`, for a --sbom audit. The one thing it
    # must not do is rebuild PURLs: npm scopes, maven group:artifact and Go module
    # paths are all easy to reconstruct subtly wrong, and the input SBOM already
    # carries the authoritative one. So each component re-emits the PURL it arrived
    # with, which means a consumer (Dependency-Track being the point of this) matches
    # our output exactly as it matched the input, now annotated with the maintenance
    # signals it had no way to compute.
    def render_sbom(result:, tool_version:, spec_version: "1.6", now: Time.now.utc)
      components = result.sort_by { |key, _| key.to_s }.map { |key, data| sbom_component(key.to_s, data) }
      vulnerabilities = result.sort_by { |key, _| key.to_s }.flat_map do |key, data|
        ref = sbom_ref(key.to_s, data)
        (data[:vulnerabilities] || []).map { |advisory| vulnerability(advisory, ref) }
      end

      document = envelope(components, spec_version, tool_version, now)
      document["vulnerabilities"] = vulnerabilities unless vulnerabilities.empty?
      JSON.pretty_generate(document)
    end

    private

    def envelope(components, spec_version, tool_version, now)
      {
        "bomFormat" => "CycloneDX",
        "specVersion" => spec_version,
        "serialNumber" => deterministic_serial(components),
        "version" => 1,
        "metadata" => {
          "timestamp" => now.iso8601,
          "tools" => [{"vendor" => "SeanLF", "name" => "still_active", "version" => tool_version}]
        },
        "components" => components
      }
    end

    # The input's own PURL identifies the component. It is always present for an
    # assessed dependency (SbomReader routes a component with no PURL to
    # `unassessable`, so it never reaches an assessment), but the composite result
    # key stands in defensively rather than emitting a component with no identity.
    def sbom_ref(key, data)
      data[:purl] || key
    end

    def sbom_component(key, data)
      ref = sbom_ref(key, data)
      component = {"type" => "library", "name" => data[:name] || key}
      component["version"] = data[:version_used] if data[:version_used]
      component["bom-ref"] = ref
      component["purl"] = data[:purl] if data[:purl]
      component["licenses"] = licenses(data[:license]) if data[:license]
      if data[:repository_url]
        component["externalReferences"] = [{"type" => "vcs", "url" => data[:repository_url]}]
      end
      properties = sbom_properties(data)
      component["properties"] = properties unless properties.empty?
      component
    end


    def build_components(result, ruby_info)
      components = result.sort_by { |name, _| name.to_s }.map { |name, data| gem_component(name.to_s, data) }
      components << ruby_component(ruby_info) if ruby_info && ruby_info[:version]
      components
    end

    def gem_component(name, data)
      version = data[:version_used]
      component = {"type" => "library", "name" => name}
      component["version"] = version if version
      component["bom-ref"] = bom_ref(name, data)
      component["purl"] = purl(name, version, data[:source_type]) if version
      component["licenses"] = licenses(data[:license]) if data[:license]
      if data[:repository_url]
        component["externalReferences"] = [{"type" => "vcs", "url" => data[:repository_url]}]
      end
      properties = gem_properties(data)
      component["properties"] = properties unless properties.empty?
      component
    end

    def bom_ref(name, data)
      version = data[:version_used]
      return purl(name, version, data[:source_type]) if version

      "#{data[:source_type]}-source:#{name}@unknown"
    end

    # Datadog SCA (and strict CycloneDX consumers) hard-reject a versioned
    # library component with no purl, so every gem with a version needs one.
    # A path gem is local and not on rubygems, so it gets pkg:generic to avoid
    # false-matching a public gem of the same name; git/rubygems-sourced gems
    # get pkg:gem so a fork still matches the upstream gem's advisories.
    def purl(name, version, source_type)
      type = (source_type == :path) ? "generic" : "gem"
      "pkg:#{type}/#{name}@#{version}"
    end

    # VersionHelper joins multiple SPDX ids with ", " for terminal/markdown
    # display; CycloneDX's license.id must be a single SPDX id, so split back
    # into one entry per license rather than emitting an invalid joined id.
    def licenses(license)
      license.split(", ").map { |id| {"license" => {"id" => id}} }
    end

    # Signals both paths compute. `status` is the folded verdict a consumer would
    # otherwise have to re-derive, which is the whole reason for emitting an
    # enriched SBOM rather than the input one.
    def shared_properties(data)
      {
        "still_active:status" => StatusHelper.gem_status(data).to_s,
        "still_active:archived" => boolean_property(data[:archived]),
        "still_active:deprecated" => boolean_property(data[:deprecated]),
        "still_active:deprecation_reason" => data[:deprecation_reason],
        "still_active:scorecard_score" => data[:scorecard_score]&.to_s,
        "still_active:libyear" => data[:libyear]&.to_s,
        "still_active:last_commit_date" => iso8601(data[:last_commit_date])
      }
    end

    def to_properties(hash)
      hash.filter_map { |name, value| {"name" => name, "value" => value} unless value.nil? }
    end

    def gem_properties(data)
      to_properties(shared_properties(data).merge(
        "still_active:version_yanked" => boolean_property(data[:version_yanked])
      ))
    end

    # Cross-ecosystem extras: which ecosystem the package came from, and whether it
    # is one the project declared (both meaningless on the Ruby-only native path).
    def sbom_properties(data)
      to_properties(shared_properties(data).merge(
        "still_active:ecosystem" => data[:ecosystem]&.to_s,
        "still_active:direct" => boolean_property(data[:direct])
      ))
    end

    # The Ruby interpreter. CycloneDX's "platform" type fits semantically, but
    # nothing consumes it and strict SCA validators (Datadog) only accept
    # "library" + a purl. We follow Syft's convention for an unmanaged runtime:
    # type "library", purl pkg:generic/ruby@<ver>, plus a CPE — the CPE is what
    # actually lets a matcher (NVD/Grype) hit interpreter CVEs, since no purl
    # type maps the Ruby runtime in OSV. The EOL/libyear signals stay as
    # still_active properties.
    def ruby_component(ruby_info)
      version = ruby_info[:version]
      {
        "type" => "library",
        "name" => "ruby",
        "version" => version,
        "bom-ref" => "pkg:generic/ruby@#{version}",
        "purl" => "pkg:generic/ruby@#{version}",
        "cpe" => "cpe:2.3:a:ruby-lang:ruby:#{version}:*:*:*:*:*:*:*",
        "properties" => [
          {"name" => "still_active:eol", "value" => boolean_property(ruby_info[:eol])},
          {"name" => "still_active:libyear", "value" => ruby_info[:libyear]&.to_s}
        ].reject { |p| p["value"].nil? }
      }
    end

    def build_vulnerabilities(result)
      result.sort_by { |name, _| name.to_s }.flat_map do |name, data|
        ref = bom_ref(name.to_s, data)
        (data[:vulnerabilities] || []).map { |advisory| vulnerability(advisory, ref) }
      end
    end

    def vulnerability(advisory, component_ref)
      entry = {
        "bom-ref" => "#{advisory[:id]}:#{component_ref}",
        "id" => advisory[:id],
        "affects" => [{"ref" => component_ref}]
      }
      entry["source"] = {"name" => advisory[:source]} if advisory[:source]
      advisory_rating = rating(advisory)
      entry["ratings"] = [advisory_rating] if advisory_rating
      entry
    end

    def rating(advisory)
      # effective_score drops deps.dev's cvss3=0 sentinel; an unscored advisory
      # gets no numeric rating (honest) rather than a masquerading 0.0. A CVSS-4-only
      # advisory now carries the OSV-computed v4 score, so it gets a real rating too.
      score = VulnerabilityHelper.effective_score(advisory)
      return if score.nil?

      rating = {"score" => score, "severity" => VulnerabilityHelper.highest_severity([advisory]) || "unknown", "method" => rating_method(advisory)}
      vector = advisory[:cvss3_vector] || advisory[:cvss_vector]
      rating["vector"] = vector if vector
      rating
    end

    # Names the CVSS version behind the score so a v4-derived rating isn't mislabelled
    # CVSSv2. deps.dev's v3/v2 win; otherwise the OSV-enriched vector's version.
    def rating_method(advisory)
      return "CVSSv3" if advisory[:cvss3_score]&.positive?
      return "CVSSv2" if advisory[:cvss2_score]&.positive?

      case advisory[:cvss_version]
      when "4.0" then "CVSSv4"
      when "2.0" then "CVSSv2"
      else "CVSSv3"
      end
    end

    def boolean_property(value)
      return if value.nil?

      value.to_s
    end

    def iso8601(time)
      return if time.nil?

      time.respond_to?(:iso8601) ? time.iso8601 : time.to_s
    end

    # Deterministic urn:uuid derived from the component identifiers, so two SBOMs
    # of the same lockfile are byte-identical (diffable; golden-test friendly).
    def deterministic_serial(components)
      basis = components.map { |c| c["bom-ref"] }.sort.join("\n")
      hex = Digest::SHA256.hexdigest(basis)
      uuid = "#{hex[0, 8]}-#{hex[8, 4]}-5#{hex[13, 3]}-8#{hex[17, 3]}-#{hex[20, 12]}"
      "urn:uuid:#{uuid}"
    end
  end
end
