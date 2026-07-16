# frozen_string_literal: true

require "json"
require "uri"
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
      "nuget" => :nuget
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

      # Only trust the prod/dev split when the generator actually marks it
      # somewhere (scope, or a dev property). syft-style SBOMs mark nothing, so an
      # unmarked component is genuinely unknown -- never assume it's production.
      # Scoped to library components: scope/properties are legal on any component
      # type (application/file/...), and a dev signal on one of those is unrelated
      # to whether the dependency library components are marked.
      marks_dev = components.any? { |c| c.is_a?(Hash) && c["type"] == "library" && dev_signal?(c) }

      deps = []
      unassessable = []
      components.each do |component|
        kind, entry = classify(component)
        entry[:production] = !dev_signal?(component) if kind == :dependency && marks_dev
        deps << entry if kind == :dependency
        unassessable << entry if kind == :unassessable
      end
      # uniq collapses a package that a generator lists more than once (e.g. Syft's
      # per-location entries); `production` is derived from each component's own
      # signal, so duplicates of the same name+version dedup cleanly unless a
      # generator marks the copies inconsistently (malformed; not observed).
      Result.new(dependencies: deps.uniq, unassessable: unassessable.uniq)
    rescue JSON::ParserError
      Result.new(dependencies: [], unassessable: [])
    end

    private

    # Whether a component is marked dev/test-only. CycloneDX `scope` (excluded =
    # not part of the product, optional = not needed at runtime) is the standard;
    # tools that don't set scope may instead emit a property (cyclonedx-npm's
    # `cdx:npm:package:development=true`). Absent both, this is false -- the caller
    # only trusts a false when the document marks dev somewhere.
    def dev_signal?(component)
      scope = component["scope"]
      return true if scope == "excluded" || scope == "optional"

      Array(component["properties"]).any? do |p|
        p.is_a?(Hash) && p["value"] == "true" && p["name"].to_s.match?(/(\A|:)dev(elopment)?\z/)
      end
    end

    # [:dependency, {...}] | [:unassessable, {...}] | nil (non-package noise).
    def classify(component)
      return unless component.is_a?(Hash) && component["type"] == "library"

      name = component["name"]
      purl = component["purl"]
      return [:unassessable, {ecosystem: nil, name: name, reason: :no_purl}] unless purl.is_a?(String) && !purl.empty?

      classify_purl(purl, name)
    end

    # Public registry hosts per ecosystem. A purl `repository_url` qualifier means
    # a non-default (private/alternative) registry per the purl spec, EXCEPT when a
    # generator redundantly names the public one -- so we still assess those.
    PUBLIC_REGISTRY_HOSTS = [
      "rubygems.org",
      "registry.npmjs.org",
      "npmjs.org",
      "registry.yarnpkg.com",
      "pypi.org",
      "files.pythonhosted.org",
      "crates.io",
      "static.crates.io",
      "index.crates.io",
      "repo1.maven.org",
      "repo.maven.apache.org",
      "api.nuget.org",
      "proxy.golang.org"
    ].freeze

    def classify_purl(purl, name)
      parsed = PackageURL.parse(purl)
      type = parsed.type&.downcase
      ecosystem = ECOSYSTEMS[type]

      if ecosystem
        return [:unassessable, {ecosystem: type, name: name, reason: :no_version}] if parsed.version.to_s.empty?

        full_name = build_name(ecosystem, parsed.namespace, parsed.name)
        repository_url = parsed.qualifiers&.dig("repository_url")
        # A private/alternative registry: never look the name up on the public
        # registry (a same-named public package's data is not this one's -- the #43
        # dependency-confusion guard, cross-ecosystem). We never dial the URL; its
        # presence alone is the signal. Limit: this can only fire when the SBOM
        # carries repository_url; a generator that omits it (Syft often can't
        # determine the source registry) leaves a private package indistinguishable
        # from a public one, so it is still assessed by name. Best-effort, not a
        # guarantee that every private package is caught.
        if repository_url && !public_registry?(repository_url)
          return [:unassessable, {ecosystem: ecosystem, name: full_name, version: parsed.version, reason: :private_registry, repository_url: repository_url}]
        end

        [:dependency, {ecosystem: ecosystem, name: full_name, version: parsed.version}]
      elsif NOISE_TYPES.include?(type)
        nil # CI actions / opaque binaries: not a package dependency
      else
        [:unassessable, {ecosystem: type, name: name, reason: :unsupported_ecosystem}]
      end
    rescue ArgumentError
      # InvalidPackageURL is a subclass of ArgumentError, but PackageURL.parse also
      # raises a BARE ArgumentError on an empty name-after-namespace (`pkg:npm/@1.0.0`)
      # or bad percent-encoding, both common in real Syft/Trivy output. Catch both so
      # one malformed component degrades to unassessable, never a backtrace that drops
      # every other dependency's verdict (SbomReader's documented "never raises").
      [:unassessable, {ecosystem: nil, name: name, reason: :malformed_purl}]
    end

    # Whether a repository_url points at a known public registry. We only read the
    # host; we never connect to it (a lockfile/SBOM-derived URL is untrusted). An
    # unparseable or non-public host reads as private, failing safe.
    def public_registry?(repository_url)
      host = registry_host(repository_url)
      !host.nil? && PUBLIC_REGISTRY_HOSTS.include?(host)
    end

    def registry_host(url)
      URI.parse(url.include?("//") ? url : "//#{url}").host&.downcase
    rescue URI::InvalidURIError
      nil
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
