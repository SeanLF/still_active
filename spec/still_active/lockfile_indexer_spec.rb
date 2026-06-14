# frozen_string_literal: true

require_relative "../../lib/helpers/lockfile_indexer"

RSpec.describe(StillActive::LockfileIndexer) do
  let(:content) { File.read(File.expand_path("../fixtures/lockfile_indexer/standard.lock", __dir__)) }

  describe(".gem_line_index") do
    subject(:index) { described_class.gem_line_index(content) }

    it("indexes simple gems at their declaration line") do
      expect(index["activesupport"]).to(eq(4))
      expect(index["diff-lcs"]).to(eq(6))
      expect(index["json"]).to(eq(7))
    end

    it("indexes gems with hyphens, dots, and digits") do
      expect(index["nokogiri-1.16.0-x86_64-darwin"]).to(eq(8))
    end

    it("indexes top-level specs even when they also appear as nested deps") do
      # rspec-core is both nested (under rspec) and a top-level spec at line 11.
      # The top-level entry is what we point findings at.
      expect(index["rspec-core"]).to(eq(11))
    end

    it("returns 1-based line numbers") do
      expect(index.values).to(all(be_a(Integer)).and(all(be > 0)))
    end

    it("does not index lines past the GEM block (e.g. RUBY VERSION block contents)") do
      expect(index).not_to(have_key("ruby"))
    end

    it("returns an empty hash for empty input") do
      expect(described_class.gem_line_index("")).to(eq({}))
    end

    it("indexes the first block when the lockfile starts with a UTF-8 BOM") do
      # A leading BOM glued to "GEM" would otherwise fail the column-0 block
      # header anchor, leaving every gem at the line-1 SARIF fallback.
      bom_lock = "﻿" + <<~LOCK
        GEM
          remote: https://rubygems.org/
          specs:
            rake (13.0.6)

        DEPENDENCIES
          rake
      LOCK

      expect(described_class.gem_line_index(bom_lock)).to(eq("rake" => 4))
    end

    it("handles GIT and PATH blocks alongside GEM") do
      mixed = <<~LOCK
        GIT
          remote: https://github.com/foo/bar.git
          specs:
            mygem (1.0.0)

        GEM
          remote: https://rubygems.org/
          specs:
            other (2.0.0)
      LOCK
      result = described_class.gem_line_index(mixed)
      expect(result["mygem"]).to(eq(4))
      expect(result["other"]).to(eq(9))
    end

    it("handles PLUGIN SOURCE blocks") do
      plugin_lock = <<~LOCK
        PLUGIN SOURCE
          remote: https://example.com/plugin
          specs:
            my-bundler-plugin (1.0.0)

        GEM
          remote: https://rubygems.org/
          specs:
            regular (2.0.0)
      LOCK
      result = described_class.gem_line_index(plugin_lock)
      expect(result["my-bundler-plugin"]).to(eq(4))
      expect(result["regular"]).to(eq(9))
    end
  end

  describe(".ruby_version_line") do
    it("returns the line right after the RUBY VERSION header") do
      line = described_class.ruby_version_line(content)
      expect(content.lines[line - 1]).to(include("ruby 3.4.0"))
    end

    it("returns 1 when RUBY VERSION section is absent") do
      no_ruby = "GEM\n  specs:\n    foo (1.0)\n"
      expect(described_class.ruby_version_line(no_ruby)).to(eq(1))
    end
  end
end
