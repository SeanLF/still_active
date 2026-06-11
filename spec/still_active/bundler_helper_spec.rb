# frozen_string_literal: true

require "tmpdir"

RSpec.describe(StillActive::BundlerHelper) do
  let(:gemfile_path) { File.join(__dir__, "fake_gemfile/Gemfile") }

  describe("#gemfile_dependencies") do
    subject(:gemfile_dependencies) { described_class.gemfile_dependencies(gemfile_path: gemfile_path) }

    it("returns the versioned gems specified in the gemfile") do
      gem_names = gemfile_dependencies.map { |dep| dep[:name] }
      expect(gem_names).to(include("rake", "rspec"))
    end

    it("includes version strings for each dependency") do
      gemfile_dependencies.each do |dep|
        expect(dep).to(have_key(:name))
        expect(dep[:version]).to(match(/\A\d+\.\d+/))
      end
    end

    it("includes source_type and source_uri for each dependency") do
      gemfile_dependencies.each do |dep|
        expect(dep[:source_type]).to(eq(:rubygems))
        expect(dep[:source_uri]).to(be_a(String))
      end
    end

    it("returns only direct dependencies, not the full locked graph") do
      gem_names = gemfile_dependencies.map { |dep| dep[:name] }
      # rspec-core and diff-lcs are locked transitive deps, not in DEPENDENCIES.
      expect(gem_names).not_to(include("rspec-core", "diff-lcs"))
    end

    context("when no lockfile sits next to the Gemfile") do
      it("raises MissingLockfileError with the absolute path and a helpful message") do
        Dir.mktmpdir do |dir|
          gemfile = File.join(dir, "Gemfile")
          File.write(gemfile, "source 'https://rubygems.org'\n")

          expect { described_class.gemfile_dependencies(gemfile_path: gemfile) }
            .to(raise_error(StillActive::MissingLockfileError) do |e|
              expect(e.message).to(include("run `bundle lock`"))
              expect(e.message).to(include(File.expand_path(gemfile)))
            end)
        end
      end
    end

    context("when the audited Gemfile contains malicious Ruby (the #37 RCE)") do
      around do |example|
        original = ENV.fetch("BUNDLE_GEMFILE", nil)
        example.run
      ensure
        ENV["BUNDLE_GEMFILE"] = original
      end

      it("never evaluates the Gemfile; it parses only the lockfile") do
        Dir.mktmpdir do |dir|
          marker = File.join(dir, "PWNED")
          File.write(File.join(dir, "Gemfile"), <<~RUBY)
            source "https://rubygems.org"
            File.write(#{marker.inspect}, "executed")
            gem "rake"
          RUBY
          File.write(File.join(dir, "Gemfile.lock"), <<~LOCK)
            GEM
              remote: https://rubygems.org/
              specs:
                rake (13.0.0)

            PLATFORMS
              ruby

            DEPENDENCIES
              rake

            BUNDLED WITH
               2.5.0
          LOCK
          # Point the ambient env at the malicious Gemfile too, to prove we
          # neither evaluate the argument nor fall back to BUNDLE_GEMFILE.
          ENV["BUNDLE_GEMFILE"] = File.join(dir, "Gemfile")

          deps = described_class.gemfile_dependencies(gemfile_path: File.join(dir, "Gemfile"))

          expect(File).not_to(exist(marker))
          expect(deps.map { |d| d[:name] }).to(eq(["rake"]))
        end
      end
    end

    context("when an explicit gemfile_path differs from the ambient BUNDLE_GEMFILE (#42)") do
      around do |example|
        original = ENV.fetch("BUNDLE_GEMFILE", nil)
        example.run
      ensure
        ENV["BUNDLE_GEMFILE"] = original
      end

      it("audits the lockfile next to the given path, not the ambient one") do
        Dir.mktmpdir do |dir|
          File.write(File.join(dir, "Gemfile"), "source 'https://rubygems.org'\n")
          File.write(File.join(dir, "Gemfile.lock"), <<~LOCK)
            GEM
              remote: https://rubygems.org/
              specs:
                only_here (4.5.6)

            DEPENDENCIES
              only_here
          LOCK
          ENV["BUNDLE_GEMFILE"] = "/nonexistent/elsewhere/Gemfile"

          deps = described_class.gemfile_dependencies(gemfile_path: File.join(dir, "Gemfile"))

          expect(deps.map { |d| d[:name] }).to(eq(["only_here"]))
        end
      end
    end

    context("when the lockfile has a PLUGIN SOURCE block") do
      it("warns and audits the non-plugin gems without touching Bundler's plugin registry") do
        Dir.mktmpdir do |dir|
          File.write(File.join(dir, "Gemfile"), "source 'https://rubygems.org'\n")
          File.write(File.join(dir, "Gemfile.lock"), <<~LOCK)
            PLUGIN SOURCE
              remote: https://example.com/plugin
              type: some_plugin
              specs:

            GEM
              remote: https://rubygems.org/
              specs:
                rake (13.0.0)

            DEPENDENCIES
              rake
          LOCK

          deps = nil
          expect { deps = described_class.gemfile_dependencies(gemfile_path: File.join(dir, "Gemfile")) }
            .to(output(/PLUGIN SOURCE/).to_stderr)
          expect(deps.map { |d| d[:name] }).to(eq(["rake"]))
        end
      end
    end
  end

  describe("#lockfile_path_for") do
    it("pairs gems.rb with gems.locked") do
      expect(described_class.lockfile_path_for("/app/gems.rb")).to(eq("/app/gems.locked"))
    end

    it("pairs any other Gemfile with <gemfile>.lock") do
      expect(described_class.lockfile_path_for("/app/Gemfile")).to(eq("/app/Gemfile.lock"))
    end
  end
end
