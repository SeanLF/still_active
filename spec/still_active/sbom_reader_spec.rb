# frozen_string_literal: true

RSpec.describe(StillActive::SbomReader) do
  subject(:deps) { described_class.read(fixture) }

  let(:fixture) { "spec/fixtures/sbom/sample.cdx.json" }

  def sbom(*components) = { "bomFormat" => "CycloneDX", "components" => components }.to_json

  it("extracts only the mappable library components (drops file/application, github, generic, null-purl)") do
    names = deps.map { |d| [d[:ecosystem], d[:name]] }
    expect(names).to(contain_exactly(
      [:pypi, "requests"],
      [:cargo, "serde"],
      [:npm, "@babel/code-frame"],
      [:maven, "com.google.guava:guava"],
      [:rubygems, "rake"],
      [:go, "github.com/gorilla/mux"],
    ))
  end

  it("reconstructs a Go module's full path from namespace + name (not just the last segment)") do
    expect(deps.map { |d| d[:name] }).to(include("github.com/gorilla/mux"))
  end

  it("carries the version per package") do
    requests = deps.find { |d| d[:name] == "requests" }
    expect(requests).to(eq({ ecosystem: :pypi, name: "requests", version: "2.31.0" }))
  end

  it("strips Syft's ?package-id qualifier") do
    expect(deps.find { |d| d[:name] == "requests" }[:version]).to(eq("2.31.0"))
  end

  it("dedups a package that appears more than once (same purl, different package-id)") do
    expect(deps.count { |d| d[:ecosystem] == :cargo && d[:name] == "serde" }).to(eq(1))
  end

  it("percent-decodes an npm scope (%40 -> @)") do
    expect(deps.map { |d| d[:name] }).to(include("@babel/code-frame"))
  end

  it("reconstructs a maven group:artifact name from namespace + name") do
    expect(deps.map { |d| d[:name] }).to(include("com.google.guava:guava"))
  end

  it("returns [] for a missing or unreadable file, without raising") do
    expect { expect(described_class.read("spec/fixtures/sbom/does-not-exist.json")).to(eq([])) }.not_to(raise_error)
  end

  it("returns [] for a non-CycloneDX / malformed JSON body, without raising") do
    expect { expect(described_class.read_string("not json")).to(eq([])) }.not_to(raise_error)
  end

  it("surfaces a malformed PURL as unassessable instead of backtracing the whole audit") do
    # PackageURL.parse raises a BARE ArgumentError (not only InvalidPackageURL) on an
    # empty name-after-namespace (`pkg:npm/@1.0.0`) or bad percent-encoding (`%zz`),
    # both common in real Syft/Trivy output. One bad component must not crash and drop
    # every other dependency's verdict.
    body = {
      components: [
        { type: "library", name: "good", purl: "pkg:npm/lodash@4.17.21" },
        { type: "library", name: "bad", purl: "pkg:npm/@1.0.0" },
        { type: "library", name: "bad2", purl: "pkg:npm/%zz@1.0.0" },
      ],
    }.to_json
    result = nil
    expect { result = described_class.parse_string(body) }.not_to(raise_error)
    expect(result.dependencies.map { |d| d[:name] }).to(eq(["lodash"]))
    expect(result.unassessable.map { |u| u[:reason] }).to(all(eq(:malformed_purl)))
  end

  describe(".parse — surfacing unassessable components (never silently drop a real dep)") do
    subject(:result) { described_class.parse(fixture) }

    it("exposes the same assessable dependencies as .read") do
      expect(result.dependencies).to(eq(described_class.read(fixture)))
    end

    it("surfaces a real dependency in an unsupported ecosystem rather than dropping it") do
      cocoapods = result.unassessable.find { |u| u[:name] == "Alamofire" }
      expect(cocoapods).to(include(reason: :unsupported_ecosystem, ecosystem: "cocoapods"))
    end

    it("surfaces a library component that has no PURL (potential git/path/local dep)") do
      expect(result.unassessable.find { |u| u[:name] == "nopurl" }).to(include(reason: :no_purl))
    end

    it("does NOT surface genuine non-package noise (GitHub Actions, generic binaries) as unassessable") do
      surfaced = result.unassessable.map { |u| u[:name] }
      expect(surfaced).not_to(include("checkout", "node"))
    end
  end

  describe("edge cases") do
    it("classifies a package from a non-public repository_url as private (never substitutes public-registry data)") do
      # A repository_url qualifier means a non-default (private/alternative)
      # registry per the purl spec. We still never dial the URL -- we use its
      # presence to refuse a public-by-name lookup, which would report a
      # same-named PUBLIC package's data as if it were this private one
      # (dependency confusion; the #43 principle, cross-ecosystem).
      body = sbom({ "type" => "library", "purl" => "pkg:pypi/internalpkg@1.0.0?repository_url=https://pypi.internal.example.com" })
      result = described_class.parse_string(body)
      expect(result.dependencies).to(eq([]))
      expect(result.unassessable).to(eq([{
        ecosystem: :pypi,
        name: "internalpkg",
        version: "1.0.0",
        reason: :private_registry,
        repository_url: "https://pypi.internal.example.com",
      }]))
    end

    it("classifies a GitHub Packages npm package as private") do
      body = sbom({ "type" => "library", "purl" => "pkg:npm/%40acme/utils@2.0.0?repository_url=https://npm.pkg.github.com" })
      result = described_class.parse_string(body)
      expect(result.dependencies).to(eq([]))
      expect(result.unassessable.first).to(include(ecosystem: :npm, name: "@acme/utils", reason: :private_registry))
    end

    it("treats a userinfo-spoofed repository_url as private (the dependency-confusion payload)") do
      # `pypi.org@evil.com` parses with host evil.com, not pypi.org -- the guard
      # must not be fooled into a public lookup.
      body = sbom({ "type" => "library", "purl" => "pkg:pypi/internalpkg@1.0.0?repository_url=https://pypi.org@evil.com" })
      expect(described_class.parse_string(body).unassessable.first).to(include(reason: :private_registry))
    end

    it("still assesses a package whose repository_url redundantly names the PUBLIC registry") do
      body = sbom({ "type" => "library", "purl" => "pkg:pypi/requests@2.0.0?repository_url=https://pypi.org" })
      expect(described_class.read_string(body)).to(eq([{ ecosystem: :pypi, name: "requests", version: "2.0.0" }]))
    end

    it("extracts a scoped (possibly private) npm package by its full @scope/name") do
      body = sbom({ "type" => "library", "purl" => "pkg:npm/%40myorg/secret@2.0.0" })
      expect(described_class.read_string(body)).to(eq([{ ecosystem: :npm, name: "@myorg/secret", version: "2.0.0" }]))
    end

    it("skips a PURL with no version (cannot be assessed)") do
      expect(described_class.read_string(sbom({ "type" => "library", "purl" => "pkg:npm/foo" }))).to(eq([]))
    end

    it("skips an unmapped ecosystem (e.g. cocoapods/conan/swift)") do
      expect(described_class.read_string(sbom({ "type" => "library", "purl" => "pkg:cocoapods/Alamofire@5.0.0" }))).to(eq([]))
    end
  end

  # Production vs dev/test separation. The signal is only trustworthy when the
  # generator marks it (CycloneDX `scope: excluded/optional`, or a tool property
  # like `cdx:npm:package:development`). syft-style SBOMs mark nothing, so we must
  # NOT assume unmarked == production: `production` is set only when the document
  # carries a dev signal somewhere, and left absent (unknown) otherwise.
  describe("dev/prod scope") do
    def lib(name, extra = {})
      { "type" => "library", "name" => name, "purl" => "pkg:npm/#{name}@1.0.0" }.merge(extra)
    end

    it("marks a scope:excluded component as not production and unmarked siblings as production") do
      deps = described_class.read_string(sbom(lib("jest", "scope" => "excluded"), lib("lodash")))
      expect(deps.find { |d| d[:name] == "jest" }[:production]).to(be(false))
      expect(deps.find { |d| d[:name] == "lodash" }[:production]).to(be(true))
    end

    it("reads the cyclonedx-npm development property as not production") do
      body = sbom(
        lib("jest", "properties" => [{ "name" => "cdx:npm:package:development", "value" => "true" }]),
        lib("lodash"),
      )
      deps = described_class.read_string(body)
      expect(deps.find { |d| d[:name] == "jest" }[:production]).to(be(false))
      expect(deps.find { |d| d[:name] == "lodash" }[:production]).to(be(true))
    end

    it("treats scope:optional as not production, scope:required as production") do
      deps = described_class.read_string(sbom(lib("opt", "scope" => "optional"), lib("req", "scope" => "required")))
      expect(deps.find { |d| d[:name] == "opt" }[:production]).to(be(false))
      expect(deps.find { |d| d[:name] == "req" }[:production]).to(be(true))
    end

    it("leaves production unknown (key absent) when the SBOM marks nothing (e.g. syft)") do
      dep = described_class.read_string(sbom(lib("lodash"))).first
      expect(dep).not_to(have_key(:production))
    end

    it("ignores dev signals on NON-library components (an excluded app/file must not flip every dep to production)") do
      # scope/properties are legal on any component type; a self-`application`
      # marked excluded must not be read as "this SBOM marks dev" and silently
      # promote every unmarked library to production.
      body = sbom({ "type" => "application", "name" => "self", "scope" => "excluded" }, lib("lodash"))
      dep = described_class.read_string(body).find { |d| d[:name] == "lodash" }
      expect(dep).not_to(have_key(:production))
    end
  end
end
