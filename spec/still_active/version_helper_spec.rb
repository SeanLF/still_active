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
      it("finds the first non-pre-release version") do
        result = described_class.find_version(versions: versions, pre_release: false)
        expect(result["number"]).to(eq("1.3.4"))
      end
    end

    context("when searching for latest pre-release") do
      it("finds the first pre-release version") do
        result = described_class.find_version(versions: versions, pre_release: true)
        expect(result["number"]).to(eq("1.0.0.rc2"))
      end
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
end
