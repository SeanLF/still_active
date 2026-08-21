# frozen_string_literal: true

require "json"
require "uri"
require "package_url"

require_relative "helpers/sbom_graph"

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
      entries_by_ref = {}
      components.each do |component|
        kind, entry = classify(component)
        entry[:production] = !dev_signal?(component) if kind == :dependency && marks_dev
        if kind == :dependency
          ref = component["bom-ref"]
          entries_by_ref[ref] = entry if ref.is_a?(String)
          deps << entry
        end
        unassessable << entry if kind == :unassessable
      end
      drop_project_components(doc, deps, entries_by_ref)
      attach_dependency_graph(doc, deps, entries_by_ref)
      # uniq collapses a package that a generator lists more than once (e.g. Syft's
      # per-location entries); `production` is derived from each component's own
      # signal, so duplicates of the same name+version dedup cleanly unless a
      # generator marks the copies inconsistently (malformed; not observed).
      Result.new(dependencies: deps.uniq, unassessable: unassessable.uniq)
    rescue JSON::ParserError
      Result.new(dependencies: [], unassessable: [])
    end

    private

    # A Syft SBOM lists the scanned project as an ordinary library component with a
    # purl, so it was classified as one of its own dependencies and assessed: no
    # registry entry, therefore no releases, therefore reported as critically stale.
    # That is a confident false verdict about the user's own code, on the workflow
    # the README recommends, and it trips --fail-if-critical.
    #
    # The project is dropped rather than surfaced as unassessable: it is not a
    # dependency we failed to assess, it is not a dependency, which is the same
    # treatment CI actions and opaque binaries already get. Nothing changes for an
    # SBOM with no dependency graph, and the rule needs the project to actually
    # depend on something, so a dependency with a missing parent edge is never
    # dropped for looking parentless.
    def drop_project_components(doc, deps, entries_by_ref)
      return if entries_by_ref.empty?

      roots = SbomGraph.project_refs(dependencies: doc["dependencies"], library_refs: entries_by_ref.keys.to_set)
      return if roots.empty?

      # Compared by identity, not value: two components can classify to equal
      # hashes, and only the one the graph named as a root should be dropped.
      dropped = roots.filter_map { |ref| entries_by_ref.delete(ref)&.object_id }.to_set
      deps.reject! { |entry| dropped.include?(entry.object_id) }
    end

    # Place each package in the CycloneDX dependency graph, so a cross-ecosystem
    # audit can say which packages you actually declared and, for the rest, the
    # declared package that pulls each one in. Same contract as the native path:
    # `direct` is a boolean, and `dependency_path` is present only for a transitive
    # package, head-first so it names the dependency a maintainer can act on.
    #
    # Both fields are attached ONLY to packages the graph actually places. A
    # generator can emit a near-empty graph (a Syft directory scan of a Ruby project
    # produced one edge across 789 components), and stamping `direct: false` on
    # everything it failed to mention would be the positive claim "none of these are
    # yours" about a document that never said. Absent means unknown, which the
    # renderers already treat correctly: they test `direct == false`, not falsiness.
    def attach_dependency_graph(doc, deps, entries_by_ref)
      return if entries_by_ref.empty?

      placements = SbomGraph.resolve(
        dependencies: doc["dependencies"],
        root_ref: doc.dig("metadata", "component", "bom-ref"),
        library_refs: entries_by_ref.keys.to_set
      )
      return if placements.nil?

      identities = entries_by_ref.transform_values { |entry| "#{entry[:ecosystem]}/#{entry[:name]}" }
      # Fold per package identity first. A generator may list one package under
      # several bom-refs (Syft emits a component per location), and those copies are
      # collapsed by `uniq` below; if they carried different placements they would
      # stop being equal and the package would appear twice in the audit.
      best = {}
      entries_by_ref.each do |ref, entry|
        placement = placements[ref]
        next if placement.nil?

        key = identity_key(entry)
        best[key] = better_placement(best[key], placement)
      end

      deps.each do |entry|
        placement = best[identity_key(entry)]
        next if placement.nil?

        entry[:direct] = placement[:direct]
        next if placement[:direct]

        path = Array(placement[:path]).filter_map { |ref| identities[ref] }
        entry[:dependency_path] = path unless path.empty?
      end
    end

    def identity_key(entry)
      [entry[:ecosystem], entry[:name], entry[:version]]
    end

    # Declared beats pulled-in (you can act on it directly), and among transitive
    # placements the shorter path wins, matching the native path's shortest-path BFS.
    def better_placement(current, candidate)
      return candidate if current.nil?
      return current if current[:direct]
      return candidate if candidate[:direct]

      (Array(candidate[:path]).length < Array(current[:path]).length) ? candidate : current
    end

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

        # The input's own PURL, kept verbatim rather than parsed-and-rebuilt. An
        # enriched SBOM re-emits it unchanged, so whatever a consumer matched on
        # the input it matches on our output, and no per-ecosystem PURL
        # reconstruction (npm scopes, maven group:artifact, go module paths) can
        # get it subtly wrong.
        [:dependency, {ecosystem: ecosystem, name: full_name, version: parsed.version, purl: preserved_purl(purl)}]
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

    # The input's PURL, kept for re-emission in an enriched SBOM, with Syft's
    # `package-id` qualifier removed. That qualifier is Syft's internal per-location
    # bookkeeping rather than part of the package's identity, and it is why the same
    # package can appear twice under two different PURLs; dropping it is what lets
    # those copies still collapse. Everything else is left byte-identical rather than
    # re-serialized through PackageURL, so a consumer that matched the input PURL
    # matches ours, with no chance of a normalization changing the encoding.
    def preserved_purl(purl)
      base, separator, query = purl.partition("?")
      return purl if separator.empty?

      kept = query.split("&").reject { |pair| pair.start_with?("package-id=") }
      kept.empty? ? base : "#{base}?#{kept.join("&")}"
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
