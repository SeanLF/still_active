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
end
