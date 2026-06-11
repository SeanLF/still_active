# frozen_string_literal: true

require "json"

RSpec.describe(StillActive::CyclonedxHelper) do
  let(:fixed_time) { Time.utc(2026, 5, 23, 12, 0, 0) }

  let(:result) do
    {
      "rack" => {
        source_type: :rubygems,
        version_used: "2.0.0",
        latest_version: "3.2.6",
        repository_url: "https://github.com/rack/rack",
        last_commit_date: Time.utc(2026, 4, 1),
        archived: false,
        scorecard_score: 6.5,
        license: "MIT",
        libyear: 4.4,
        version_yanked: false,
        vulnerability_count: 1,
        vulnerabilities: [
          { id: "GHSA-xxx", url: "https://osv.dev/GHSA-xxx", title: "XSS", aliases: ["CVE-1"], cvss3_score: 7.5, cvss3_vector: "CVSS:3.1/AV:N", cvss2_score: nil, source: "merged" },
        ],
      },
      "local_gem" => {
        source_type: :path,
        version_used: "0.1.0",
        license: nil,
        vulnerability_count: 0,
        vulnerabilities: [],
      },
    }
  end

  let(:ruby_info) { { version: "3.4.0", eol: false, libyear: 0.0 } }

  def render(spec_version: "1.6")
    JSON.parse(described_class.render(result: result, ruby_info: ruby_info, tool_version: "1.5.0", spec_version: spec_version, now: fixed_time))
  end

  it("emits a CycloneDX document with the default spec version 1.6") do
    doc = render
    expect(doc["bomFormat"]).to(eq("CycloneDX"))
    expect(doc["specVersion"]).to(eq("1.6"))
  end

  it("emits the requested spec version 1.7 with identical structure") do
    expect(render(spec_version: "1.7")["specVersion"]).to(eq("1.7"))
  end

  it("stamps the injected timestamp") do
    expect(render["metadata"]["timestamp"]).to(eq("2026-05-23T12:00:00Z"))
  end

  it("produces a deterministic serialNumber for identical input") do
    first = described_class.render(result: result, ruby_info: ruby_info, tool_version: "1.5.0", now: fixed_time)
    second = described_class.render(result: result, ruby_info: ruby_info, tool_version: "1.5.0", now: fixed_time)
    expect(JSON.parse(first)["serialNumber"]).to(eq(JSON.parse(second)["serialNumber"]))
    expect(JSON.parse(first)["serialNumber"]).to(match(/\Aurn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/))
  end

  describe("components") do
    subject(:components) { render["components"] }

    it("gives a rubygems gem a pkg:gem purl and matching bom-ref") do
      rack = components.find { |c| c["name"] == "rack" }
      expect(rack["purl"]).to(eq("pkg:gem/rack@2.0.0"))
      expect(rack["bom-ref"]).to(eq("pkg:gem/rack@2.0.0"))
      expect(rack["type"]).to(eq("library"))
    end

    it("maps the license to the licenses array") do
      rack = components.find { |c| c["name"] == "rack" }
      expect(rack["licenses"]).to(eq([{ "license" => { "id" => "MIT" } }]))
    end

    it("splits a multi-license gem into one valid SPDX entry each (not a comma-joined id)") do
      result["multi"] = { source_type: :rubygems, version_used: "1.0.0", license: "Hippocratic-2.1, MIT", vulnerability_count: 0, vulnerabilities: [] }
      multi = components.find { |c| c["name"] == "multi" }
      expect(multi["licenses"]).to(eq([
        { "license" => { "id" => "Hippocratic-2.1" } },
        { "license" => { "id" => "MIT" } },
      ]))
    end

    it("carries the repository URL as a vcs externalReference") do
      rack = components.find { |c| c["name"] == "rack" }
      expect(rack["externalReferences"]).to(include("type" => "vcs", "url" => "https://github.com/rack/rack"))
    end

    it("puts maintenance signals in still_active-namespaced properties") do
      rack = components.find { |c| c["name"] == "rack" }
      props = rack["properties"].to_h { |p| [p["name"], p["value"]] }
      expect(props).to(include(
        "still_active:archived" => "false",
        "still_active:scorecard_score" => "6.5",
        "still_active:libyear" => "4.4",
      ))
    end

    it("gives a path-sourced gem a pkg:generic purl (avoids false rubygems vuln matches)") do
      local = components.find { |c| c["name"] == "local_gem" }
      expect(local["purl"]).to(eq("pkg:generic/local_gem@0.1.0"))
      expect(local["bom-ref"]).to(eq("pkg:generic/local_gem@0.1.0"))
    end

    it("gives a git-sourced gem a pkg:gem purl (matches upstream advisories for forks)") do
      result["forked"] = { source_type: :git, version_used: "1.2.3" }
      forked = components.find { |c| c["name"] == "forked" }
      expect(forked["purl"]).to(eq("pkg:gem/forked@1.2.3"))
      expect(forked["bom-ref"]).to(eq("pkg:gem/forked@1.2.3"))
    end

    it("gives every versioned component a purl (CycloneDX/SCA ingestion requirement)") do
      versioned = components.select { |c| c["version"] }
      expect(versioned).not_to(be_empty)
      expect(versioned).to(all(have_key("purl")))
    end

    it("emits Ruby as a library with a pkg:generic purl and CPE (portable + ingestible)") do
      ruby = components.find { |c| c["name"] == "ruby" }
      expect(ruby["type"]).to(eq("library"))
      expect(ruby["version"]).to(eq("3.4.0"))
      expect(ruby["purl"]).to(eq("pkg:generic/ruby@3.4.0"))
      expect(ruby["cpe"]).to(eq("cpe:2.3:a:ruby-lang:ruby:3.4.0:*:*:*:*:*:*:*"))
    end

    it("keeps the Ruby EOL/libyear maintenance signals as properties") do
      ruby = components.find { |c| c["name"] == "ruby" }
      props = ruby["properties"].to_h { |p| [p["name"], p["value"]] }
      expect(props).to(include("still_active:eol" => "false", "still_active:libyear" => "0.0"))
    end
  end

  describe("vulnerabilities") do
    subject(:vulnerabilities) { render["vulnerabilities"] }

    it("emits one entry per advisory, referencing the affected component") do
      expect(vulnerabilities.length).to(eq(1))
      vuln = vulnerabilities.first
      expect(vuln["id"]).to(eq("GHSA-xxx"))
      expect(vuln["affects"]).to(eq([{ "ref" => "pkg:gem/rack@2.0.0" }]))
    end

    it("maps CVSS into a rating with severity and vector") do
      rating = vulnerabilities.first["ratings"].first
      expect(rating).to(include("score" => 7.5, "severity" => "high", "method" => "CVSSv3", "vector" => "CVSS:3.1/AV:N"))
    end

    it("records the advisory source") do
      expect(vulnerabilities.first["source"]).to(eq({ "name" => "merged" }))
    end

    it("references only components that exist in the BOM") do
      refs = render["components"].map { |c| c["bom-ref"] }
      vulnerabilities.each do |v|
        v["affects"].each { |a| expect(refs).to(include(a["ref"])) }
      end
    end
  end
end
