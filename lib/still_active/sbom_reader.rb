# frozen_string_literal: true

require "json"
require "package_url"

module StillActive
  # Reads a CycloneDX SBOM (e.g. produced by Syft) into a clean, normalized
  # dependency set -- the breadth input for non-Ruby ecosystems, where the
  # maintenance lens runs over deps.dev/ecosyste.ms.
  #
  # `parse` returns both the assessable dependencies AND the components it could
  # NOT assess (a real dependency in an unsupported ecosystem, or a library with
  # no PURL -- typically a git/path/local source). Surfacing those is the point:
  # silently dropping them would let an audit report "all clear" while ignoring
  # the deps that are often the riskiest. Genuine non-package noise (GitHub
  # Actions `pkg:github`, opaque binaries `pkg:generic`, and file/application
  # components) is excluded, not surfaced.
  #
  # `read` keeps the simple "just the dependencies" shape. Never raises -- a
  # missing/malformed SBOM or a bad PURL degrades to empty/skip.
  module SbomReader
    extend self

    Result = Data.define(:dependencies, :unassessable)

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

    # PURL types that are not package dependencies: CI actions and opaque
    # binaries. Excluded from both lists (not "unassessed deps").
    NOISE_TYPES = ["github", "generic"].freeze

    def read(path) = parse(path).dependencies
    def read_string(body) = parse_string(body).dependencies

    def parse(path)
      parse_string(File.read(path))
    rescue SystemCallError, IOError
      Result.new(dependencies: [], unassessable: [])
    end

    def parse_string(body)
      doc = JSON.parse(body)
      components = doc.is_a?(Hash) ? doc["components"] : nil
      return Result.new(dependencies: [], unassessable: []) unless components.is_a?(Array)

      deps = []
      unassessable = []
      components.each do |component|
        kind, entry = classify(component)
        deps << entry if kind == :dependency
        unassessable << entry if kind == :unassessable
      end
      Result.new(dependencies: deps.uniq, unassessable: unassessable.uniq)
    rescue JSON::ParserError
      Result.new(dependencies: [], unassessable: [])
    end

    private

    # [:dependency, {...}] | [:unassessable, {...}] | nil (non-package noise).
    def classify(component)
      return unless component.is_a?(Hash) && component["type"] == "library"

      name = component["name"]
      purl = component["purl"]
      return [:unassessable, { ecosystem: nil, name: name, reason: :no_purl }] unless purl.is_a?(String) && !purl.empty?

      classify_purl(purl, name)
    end

    def classify_purl(purl, name)
      parsed = PackageURL.parse(purl)
      type = parsed.type&.downcase
      ecosystem = ECOSYSTEMS[type]

      if ecosystem
        return [:unassessable, { ecosystem: type, name: name, reason: :no_version }] if parsed.version.to_s.empty?

        [:dependency, { ecosystem: ecosystem, name: build_name(ecosystem, parsed.namespace, parsed.name), version: parsed.version }]
      elsif NOISE_TYPES.include?(type)
        nil # CI actions / opaque binaries: not a package dependency
      else
        [:unassessable, { ecosystem: type, name: name, reason: :unsupported_ecosystem }]
      end
    rescue PackageURL::InvalidPackageURL
      [:unassessable, { ecosystem: nil, name: name, reason: :malformed_purl }]
    end

    # Reconstruct the lookup name from the PURL's namespace + name: npm
    # `@scope/name`, maven `group:artifact`, Go module path `github.com/owner/name`;
    # pypi/cargo/gem/nuget have no namespace and use the bare name.
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
