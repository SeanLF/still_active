# frozen_string_literal: true

require "json"
require "package_url"

module StillActive
  # Reads a CycloneDX SBOM (e.g. produced by Syft) into a clean, normalized
  # dependency set -- the breadth input for non-Ruby ecosystems, where the
  # maintenance lens runs over deps.dev/ecosyste.ms. Encodes the filtering
  # recipe validated against real repos:
  #   - only `type: library` components (file/application carry no PURL);
  #   - map the PURL type to an ecosystem we can look up; drop the rest
  #     (pkg:github = GitHub Actions, pkg:generic = opaque binaries);
  #   - strip Syft's `?package-id` qualifier and `#subpath`;
  #   - reconstruct the registry name (npm `@scope/name`, maven `group:artifact`);
  #   - dedup, since the same package surfaces from manifest + lock + install.
  # Returns [{ ecosystem:, name:, version: }]. Never raises -- a bad/missing SBOM
  # yields [], so a best-effort breadth input can't crash the run.
  module SbomReader
    extend self

    # PURL type -> still_active ecosystem (also the deps.dev `system`, lowercased).
    ECOSYSTEMS = {
      "gem" => :rubygems,
      "npm" => :npm,
      "pypi" => :pypi,
      "cargo" => :cargo,
      "maven" => :maven,
      "golang" => :go,
      "nuget" => :nuget,
    }.freeze

    def read(path)
      read_string(File.read(path))
    rescue SystemCallError, IOError
      [] # missing/unreadable file -> no deps, never raise
    end

    def read_string(body)
      doc = JSON.parse(body)
      components = doc.is_a?(Hash) ? doc["components"] : nil
      return [] unless components.is_a?(Array)

      components.filter_map { |component| component_to_dep(component) }.uniq
    rescue JSON::ParserError
      []
    end

    private

    def component_to_dep(component)
      return unless component.is_a?(Hash) && component["type"] == "library"

      purl = component["purl"]
      return unless purl.is_a?(String) && !purl.empty?

      parse_purl(purl)
    end

    # Parse via the official package-url gem (spec-compliant: percent-decoding,
    # qualifier/subpath stripping, namespace handling). A malformed PURL on one
    # component is skipped, not fatal -- a best-effort breadth input must never
    # crash the read.
    def parse_purl(purl)
      parsed = PackageURL.parse(purl)
      ecosystem = ECOSYSTEMS[parsed.type&.downcase]
      return if ecosystem.nil? || parsed.name.to_s.empty? || parsed.version.to_s.empty?

      { ecosystem: ecosystem, name: build_name(ecosystem, parsed.namespace, parsed.name), version: parsed.version }
    rescue PackageURL::InvalidPackageURL
      nil # one malformed PURL must not kill the read; a real bug still surfaces
    end

    # Reconstruct the lookup name from the PURL's namespace + name. The namespace
    # carries the npm scope (`@scope/name`), the maven group (`group:artifact`),
    # and the Go module path prefix (`github.com/owner/name`); pypi/cargo/gem/
    # nuget have no namespace and use the bare name.
    def build_name(ecosystem, namespace, name)
      return name if namespace.to_s.empty?

      case ecosystem
      when :npm, :go then "#{namespace}/#{name}"
      when :maven then "#{namespace}:#{name}"
      else name
      end
    end
  end
end
