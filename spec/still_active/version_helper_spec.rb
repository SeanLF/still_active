# frozen_string_literal: true

require "json"

RSpec.describe(StillActive::VersionHelper) do
  let(:versions) { JSON.parse(File.read("fixtures/debug_versions.json")) }
  let(:still_active_version) { JSON.parse(File.read("fixtures/still_active_version.json")) }

  describe("#find_version") do
    context("when versions is nil") do
      it("returns nil") do
        expect(described_class.find_version(versions: nil)).to(be_nil)
      end
    end

    context("when searching by version string") do
      it("finds the matching version") do
        result = described_class.find_version(versions: versions, version_string: "1.3.4")
        expect(result["number"]).to(eq("1.3.4"))
      end

      it("returns nil when version string matches but pre_release filter excludes it") do
        result = described_class.find_version(versions: versions, version_string: "1.3.4", pre_release: true)
        expect(result).to(be_nil)
      end
    end

    context("when searching for latest release") do
      it("finds the highest non-pre-release version") do
        result = described_class.find_version(versions: versions, pre_release: false)
        expect(result["number"]).to(eq("1.3.4"))
      end

      it("returns the highest stable version, not whichever the source lists first") do
        # Some sources (e.g. GitHub Packages) return versions unsorted; relying
        # on newest-first ordering would report the wrong "latest" and cascade a
        # bogus up_to_date / libyear off it.
        unordered = [
          { "number" => "1.0.0", "prerelease" => false },
          { "number" => "2.5.0", "prerelease" => false },
          { "number" => "2.0.0", "prerelease" => false },
        ]
        result = described_class.find_version(versions: unordered, pre_release: false)
        expect(result["number"]).to(eq("2.5.0"))
      end
    end

    context("when searching for latest pre-release") do
      it("finds the highest pre-release version") do
        result = described_class.find_version(versions: versions, pre_release: true)
        expect(result["number"]).to(eq("1.0.0.rc2"))
      end

      it("returns the highest pre-release, not whichever is listed first") do
        unordered = [
          { "number" => "1.0.0.rc1", "prerelease" => true },
          { "number" => "1.0.0.rc3", "prerelease" => true },
          { "number" => "1.0.0.rc2", "prerelease" => true },
        ]
        result = described_class.find_version(versions: unordered, pre_release: true)
        expect(result["number"]).to(eq("1.0.0.rc3"))
      end
    end
  end

  describe("#upcoming_pre_release") do
    it("returns nil when there is no pre-release") do
      expect(described_class.upcoming_pre_release(pre_release: nil, release: { "number" => "1.0.0" })).to(be_nil)
    end

    it("keeps a pre-release newer than the latest stable (an upcoming version)") do
      pre = { "number" => "2.0.0.rc1", "prerelease" => true }
      expect(described_class.upcoming_pre_release(pre_release: pre, release: { "number" => "1.5.0" })).to(eq(pre))
    end

    it("drops a pre-release older than the latest stable (historical noise)") do
      # e.g. an 8.1.0.rc1 lingering after 8.1.2 shipped, or a lone 2009 rc on a
      # gem now at 0.9.x. Showing it is noise, and it marks a behind gem as ahead.
      pre = { "number" => "0.3.4.rc2", "prerelease" => true }
      expect(described_class.upcoming_pre_release(pre_release: pre, release: { "number" => "0.9.11" })).to(be_nil)
    end

    it("drops a pre-release of an already-shipped stable (rc1 sorts below its release)") do
      pre = { "number" => "1.0.0.rc1", "prerelease" => true }
      expect(described_class.upcoming_pre_release(pre_release: pre, release: { "number" => "1.0.0" })).to(be_nil)
    end

    it("keeps the pre-release when there is no stable release at all") do
      pre = { "number" => "1.0.0.rc1", "prerelease" => true }
      expect(described_class.upcoming_pre_release(pre_release: pre, release: nil)).to(eq(pre))
    end

    it("drops the pre-release when its version cannot be compared") do
      pre = { "number" => "not-a-version", "prerelease" => true }
      expect(described_class.upcoming_pre_release(pre_release: pre, release: { "number" => "1.0.0" })).to(be_nil)
    end
  end

  describe("#up_to_date") do
    it("returns nil when both latest versions are nil") do
      expect(described_class.up_to_date(version_used: nil, latest_version: nil)).to(be_nil)
    end

    it("returns nil when version_used is nil but latest exists") do
      expect(described_class.up_to_date(version_used: nil, latest_version: "1.0.0")).to(be_nil)
    end

    it("returns true when on latest release") do
      expect(described_class.up_to_date(version_used: "1.0.0", latest_version: "1.0.0")).to(be(true))
    end

    it("returns true when on latest release with older pre-release") do
      expect(described_class.up_to_date(version_used: "1.0.0", latest_version: "1.0.0", latest_pre_release_version: "3.0.0rc1")).to(be(true))
    end

    it("returns false when behind latest release") do
      expect(described_class.up_to_date(version_used: "1.0.0", latest_version: "2.0.0")).to(be(false))
    end

    it("returns false when behind both latest and pre-release") do
      expect(described_class.up_to_date(version_used: "1.0.0", latest_version: "2.0.0", latest_pre_release_version: "3.0.0rc1")).to(be(false))
    end

    it("returns false when behind pre-release only") do
      expect(described_class.up_to_date(version_used: "1.0.0", latest_version: nil, latest_pre_release_version: "3.0.0rc1")).to(be(false))
    end

    it("returns true when on pre-release matching latest pre-release") do
      expect(described_class.up_to_date(version_used: "3.0.0rc1", latest_version: "2.0.0", latest_pre_release_version: "3.0.0rc1")).to(be(true))
    end

    it("returns true when on pre-release with no stable release") do
      expect(described_class.up_to_date(version_used: "3.0.0rc1", latest_version: nil, latest_pre_release_version: "3.0.0rc1")).to(be(true))
    end

    it("returns nil for malformed version strings without raising") do
      expect(described_class.up_to_date(version_used: "not-a-version", latest_version: "1.0.0")).to(be_nil)
    end

    it("returns false when latest version is malformed") do
      expect(described_class.up_to_date(version_used: "1.0.0", latest_version: "abc.def")).to(be(false))
    end

    # Go module versions are "v"-prefixed semver (v2.0.1); the prefix is not part
    # of the version and Gem::Version can't parse it. Without stripping it, a
    # current Go dependency read as "behind" (the SBOM terminal/markdown table
    # painted a "v2.0.1 -> v2.0.1" upgrade arrow on an up-to-date package).
    it("treats a Go v-prefixed version as up to date when it matches latest") do
      expect(described_class.up_to_date(version_used: "v2.0.1", latest_version: "v2.0.1")).to(be(true))
    end

    it("treats a Go v-prefixed version as behind when older than latest") do
      expect(described_class.up_to_date(version_used: "v2.0.0", latest_version: "v2.1.0")).to(be(false))
    end

    # SemVer build metadata (cargo's "1.0.4+wasi-0.2.12", "0.14.7+wasi-0.2.4")
    # MUST be ignored for precedence (SemVer 2.0.0 sec 10). Gem::Version can't
    # parse the "+", so without stripping it, up_to_date returned nil and the
    # terminal painted a "behind" arrow on an already-current cargo dependency.
    it("ignores SemVer build metadata, so an identical +build version reads as up to date") do
      expect(described_class.up_to_date(version_used: "1.0.4+wasi-0.2.12", latest_version: "1.0.4+wasi-0.2.12")).to(be(true))
    end

    it("compares versions by their core, ignoring build metadata") do
      expect(described_class.up_to_date(version_used: "0.11.1+wasi-snapshot", latest_version: "0.14.7+wasi-0.2.4")).to(be(false))
    end
  end

  describe("#to_semver") do
    # Exact gem-version -> SemVer-2.0.0 mappings. Asserting the precise output
    # (rather than matching a SemVer regex) proves correctness AND keeps a complex
    # regex out of the suite, which a ReDoS/security scanner could flag.
    {
      "3.0.0" => "3.0.0",            # plain release, already SemVer, unchanged
      "2.0.0" => "2.0.0",
      "3.0.0.rc4" => "3.0.0-rc4",    # gem prerelease dot -> SemVer hyphen
      "0.1.0.beta1" => "0.1.0-beta1",
      "1.2.3.pre.5" => "1.2.3-pre.5", # dotted prerelease structure preserved
      "2.0.0.rc.2" => "2.0.0-rc.2",
      "1.2" => "1.2.0", # short release padded to MAJOR.MINOR.PATCH
    }.each do |gem_version, semver|
      it("converts #{gem_version.inspect} to #{semver.inspect}") do
        expect(described_class.to_semver(gem_version)).to(eq(semver))
      end
    end

    it("returns a non-numeric-led string unchanged rather than fabricating a version") do
      expect(described_class.to_semver("not-a-version")).to(eq("not-a-version"))
    end

    it("returns nil/empty input unchanged") do
      expect(described_class.to_semver(nil)).to(be_nil)
      expect(described_class.to_semver("")).to(eq(""))
    end
  end

  describe("#gem_version") do
    it("returns nil for nil input") do
      expect(described_class.gem_version(version_hash: nil)).to(be_nil)
    end

    it("extracts the version number") do
      expect(described_class.gem_version(version_hash: still_active_version)).to(eq("0.1.0"))
    end
  end

  describe("#release_date") do
    it("returns nil for nil input") do
      expect(described_class.release_date(version_hash: nil)).to(be_nil)
    end

    it("parses the created_at timestamp") do
      expect(described_class.release_date(version_hash: still_active_version)).to(eq(Time.parse("2021-11-07T13:07:51.346Z")))
    end
  end

  describe("#license") do
    it("returns nil for nil input") do
      expect(described_class.license(version_hash: nil)).to(be_nil)
    end

    it("returns the single SPDX identifier") do
      expect(described_class.license(version_hash: { "licenses" => ["MIT"] })).to(eq("MIT"))
    end

    it("joins multiple licenses with a comma") do
      expect(described_class.license(version_hash: { "licenses" => ["MIT", "Apache-2.0"] })).to(eq("MIT, Apache-2.0"))
    end

    it("returns nil when the licenses array is empty") do
      expect(described_class.license(version_hash: { "licenses" => [] })).to(be_nil)
    end

    it("returns nil when the licenses key is absent") do
      expect(described_class.license(version_hash: { "number" => "1.0.0" })).to(be_nil)
    end

    it("returns nil when licenses is null") do
      expect(described_class.license(version_hash: { "licenses" => nil })).to(be_nil)
    end
  end
end
