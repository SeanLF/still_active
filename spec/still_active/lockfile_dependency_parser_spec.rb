# frozen_string_literal: true

require_relative "../../lib/helpers/lockfile_dependency_parser"

RSpec.describe(StillActive::LockfileDependencyParser) do
  describe(".parse") do
    it("extracts rubygems specs with name, version, and the source remote") do
      result = described_class.parse(<<~LOCK)
        GEM
          remote: https://rubygems.org/
          specs:
            rake (13.0.6)
            rspec (3.10.0)
              rspec-core (~> 3.10.0)

        DEPENDENCIES
          rake
      LOCK

      rake = result[:specs].find { |s| s.name == "rake" }
      expect(rake).to(have_attributes(version: "13.0.6", source_type: :rubygems, source_uri: "https://rubygems.org/"))
      expect(result[:direct]).to(eq(["rake"]))
    end

    it("ignores nested (transitive) dependency lines indented six spaces") do
      result = described_class.parse(<<~LOCK)
        GEM
          remote: https://rubygems.org/
          specs:
            rspec (3.10.0)
              rspec-core (~> 3.10.0)
            rspec-core (3.10.1)

        DEPENDENCIES
          rspec
      LOCK

      # rspec-core appears both as a nested dep (6-space) and a real spec
      # (4-space). Only the real spec is captured.
      expect(result[:specs].map(&:name)).to(contain_exactly("rspec", "rspec-core"))
    end

    it("captures a spec even when the line carries a trailing inline checksum") do
      # Bundler's grammar allows an optional checksum after the version. A
      # hand-crafted lockfile could use it to hide a gem from the audit; we
      # must still capture it.
      result = described_class.parse(<<~LOCK)
        GEM
          remote: https://rubygems.org/
          specs:
            rake (13.0.6) sha256=deadbeefcafe

        DEPENDENCIES
          rake
      LOCK

      rake = result[:specs].find { |s| s.name == "rake" }
      expect(rake).to(have_attributes(name: "rake", version: "13.0.6"))
    end

    it("strips the platform suffix from a platform-specific version") do
      result = described_class.parse(<<~LOCK)
        GEM
          remote: https://rubygems.org/
          specs:
            nokogiri (1.16.0-x86_64-linux)

        DEPENDENCIES
          nokogiri
      LOCK

      expect(result[:specs].first.version).to(eq("1.16.0"))
    end

    it("reads git sources as :git with the git URI") do
      result = described_class.parse(<<~LOCK)
        GIT
          remote: https://github.com/foo/bar.git
          revision: abc123
          specs:
            bar (1.2.0)

        DEPENDENCIES
          bar!
      LOCK

      expect(result[:specs].first).to(have_attributes(name: "bar", source_type: :git, source_uri: "https://github.com/foo/bar.git"))
      expect(result[:direct]).to(eq(["bar"]))
    end

    it("reads path sources as :path with the path") do
      result = described_class.parse(<<~LOCK)
        PATH
          remote: ../local
          specs:
            baz (0.1.0)

        DEPENDENCIES
          baz!
      LOCK

      expect(result[:specs].first).to(have_attributes(name: "baz", source_type: :path, source_uri: "../local"))
    end

    it("keeps the first remote when a GEM block lists several") do
      result = described_class.parse(<<~LOCK)
        GEM
          remote: https://first.example.com/
          remote: https://second.example.com/
          specs:
            gem_a (1.0.0)

        DEPENDENCIES
          gem_a
      LOCK

      expect(result[:specs].first.source_uri).to(eq("https://first.example.com/"))
    end

    it("flags a PLUGIN SOURCE block and yields none of its specs") do
      result = described_class.parse(<<~LOCK)
        PLUGIN SOURCE
          remote: https://example.com/plugin
          type: some_plugin
          specs:
            evil_plugin (9.9.9)

        GEM
          remote: https://rubygems.org/
          specs:
            rake (13.0.0)

        DEPENDENCIES
          rake
          evil_plugin
      LOCK

      expect(result[:plugin_source?]).to(be(true))
      expect(result[:specs].map(&:name)).to(eq(["rake"]))
    end

    it("does not flag PLUGIN SOURCE when there is none") do
      result = described_class.parse(<<~LOCK)
        GEM
          remote: https://rubygems.org/
          specs:
            rake (13.0.0)

        DEPENDENCIES
          rake
      LOCK

      expect(result[:plugin_source?]).to(be(false))
    end

    it("reads DEPENDENCIES names, dropping version constraints and pin markers") do
      result = described_class.parse(<<~LOCK)
        DEPENDENCIES
          rake (~> 13.0)
          bar!
          plain
      LOCK

      expect(result[:direct]).to(eq(["rake", "bar", "plain"]))
    end

    it("captures each spec's nested runtime dependencies (6-space lines)") do
      result = described_class.parse(<<~LOCK)
        PATH
          remote: .
          specs:
            my_gem (1.0.0)
              async (~> 2.2)
              octokit (>= 9.0, < 11)

        GEM
          remote: https://rubygems.org/
          specs:
            async (2.2.0)
            octokit (9.0.0)

        DEPENDENCIES
          my_gem!
      LOCK

      expect(result[:specs].find { |s| s.name == "my_gem" }.dependencies).to(eq(["async", "octokit"]))
      # A leaf gem with no nested lines has an empty dependency list.
      expect(result[:specs].find { |s| s.name == "async" }.dependencies).to(eq([]))
    end
  end
end
