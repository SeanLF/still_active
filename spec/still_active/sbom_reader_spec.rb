# frozen_string_literal: true

RSpec.describe(StillActive::SbomReader) do
  subject(:deps) { described_class.read(fixture) }

  let(:fixture) { "spec/fixtures/sbom/sample.cdx.json" }

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

  describe("edge cases") do
    def sbom(*components) = { "bomFormat" => "CycloneDX", "components" => components }.to_json

    it("ignores a private repository_url qualifier (untrusted lockfile-derived input) yet still extracts the package") do
      # The lens must never call a registry URL taken from the SBOM; we key only
      # on ecosystem/name/version and look those up on the trusted public APIs.
      body = sbom({ "type" => "library", "purl" => "pkg:pypi/internalpkg@1.0.0?repository_url=https://pypi.internal.example.com" })
      expect(described_class.read_string(body)).to(eq([{ ecosystem: :pypi, name: "internalpkg", version: "1.0.0" }]))
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
end
