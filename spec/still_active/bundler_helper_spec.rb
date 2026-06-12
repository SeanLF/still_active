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

    it("audits the full transitive lockfile graph by default") do
      gem_names = gemfile_dependencies.map { |dep| dep[:name] }
      # rspec-core and diff-lcs are locked transitive deps, not in DEPENDENCIES.
      expect(gem_names).to(include("rake", "rspec", "rspec-core", "diff-lcs", "rspec-support"))
    end

    it("marks DEPENDENCIES entries direct and the rest transitive") do
      by_name = gemfile_dependencies.to_h { |dep| [dep[:name], dep] }
      expect(by_name["rspec"][:direct]).to(be(true))
      expect(by_name["rake"][:direct]).to(be(true))
      expect(by_name["rspec-core"][:direct]).to(be(false))
      expect(by_name["diff-lcs"][:direct]).to(be(false))
    end

    it("gives each transitive gem a dependency path headed by a direct parent") do
      by_name = gemfile_dependencies.to_h { |dep| [dep[:name], dep] }
      # rspec -> rspec-core (rspec declares it directly)
      expect(by_name["rspec-core"][:dependency_path]).to(eq(["rspec", "rspec-core"]))
      # diff-lcs is reached via rspec -> rspec-expectations (or -mocks) -> diff-lcs
      path = by_name["diff-lcs"][:dependency_path]
      expect(path.first).to(eq("rspec"))
      expect(path.last).to(eq("diff-lcs"))
    end

    it("does not attach a dependency_path to direct deps") do
      by_name = gemfile_dependencies.to_h { |dep| [dep[:name], dep] }
      expect(by_name["rspec"][:dependency_path]).to(be_nil)
    end

    context("with config.direct_only set (the --direct-only opt-out)") do
      before { StillActive.config.direct_only = true }

      after { StillActive.reset }

      it("returns only direct dependencies, not the full locked graph") do
        gem_names = gemfile_dependencies.map { |dep| dep[:name] }
        expect(gem_names).to(include("rake", "rspec"))
        expect(gem_names).not_to(include("rspec-core", "diff-lcs"))
      end
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

    context("when the project is itself a gem (gemspec / local engine)") do
      # The #41 selective expansion (declared deps + local engine runtime deps,
      # but NOT a regular gem's transitive graph) is the --direct-only scope; the
      # default now audits the whole graph, so pin these to direct-only.
      before { StillActive.config.direct_only = true }

      after { StillActive.reset }

      # gemspec surfaces the local gem's *development* deps in DEPENDENCIES, but
      # its *runtime* deps arrive only as the path gem's nested lockfile deps.
      def write_project(dir, lockfile)
        File.write(File.join(dir, "Gemfile"), "source 'https://rubygems.org'\n")
        File.write(File.join(dir, "Gemfile.lock"), lockfile)
        described_class.gemfile_dependencies(gemfile_path: File.join(dir, "Gemfile")).map { |d| d[:name] }
      end

      it("audits the local gem's runtime deps, not just its dev deps") do
        Dir.mktmpdir do |dir|
          names = write_project(dir, <<~LOCK)
            PATH
              remote: .
              specs:
                my_gem (1.0.0)
                  octokit (~> 9.0)
                  async (~> 2.2)

            GEM
              remote: https://rubygems.org/
              specs:
                async (2.2.0)
                octokit (9.0.0)
                rspec (3.12.0)
                  rspec-core (~> 3.12)
                rspec-core (3.12.0)

            DEPENDENCIES
              my_gem!
              rspec
          LOCK

          expect(names).to(include("octokit", "async")) # runtime deps of the local gem
          expect(names).to(include("rspec"))             # dev dep, already in DEPENDENCIES
          expect(names).to(include("my_gem"))            # the local gem itself
          # A regular gem's transitive deps are still NOT audited.
          expect(names).not_to(include("rspec-core"))
        end
      end

      it("follows nested local engines transitively (path -> path)") do
        Dir.mktmpdir do |dir|
          names = write_project(dir, <<~LOCK)
            PATH
              remote: engines/a
              specs:
                engine_a (1.0.0)
                  engine_b (= 1.0.0)
                  rake (~> 13.0)

            PATH
              remote: engines/b
              specs:
                engine_b (1.0.0)
                  faraday (~> 2.0)

            GEM
              remote: https://rubygems.org/
              specs:
                faraday (2.9.0)
                rake (13.0.0)

            DEPENDENCIES
              engine_a!
          LOCK

          # engine_a -> engine_b -> faraday all reached; rake (engine_a's dep) too.
          expect(names).to(include("engine_a", "engine_b", "faraday", "rake"))
        end
      end

      it("terminates on a cyclic path-gem graph (hand-crafted lockfile)") do
        Dir.mktmpdir do |dir|
          # a -> b -> a: a lockfile can't normally cycle, but the input is
          # untrusted, so the worklist must not spin forever.
          names = write_project(dir, <<~LOCK)
            PATH
              remote: engines/a
              specs:
                engine_a (1.0.0)
                  engine_b (= 1.0.0)

            PATH
              remote: engines/b
              specs:
                engine_b (1.0.0)
                  engine_a (= 1.0.0)

            DEPENDENCIES
              engine_a!
          LOCK

          expect(names).to(contain_exactly("engine_a", "engine_b"))
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
