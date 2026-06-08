# frozen_string_literal: true

RSpec.describe(StillActive::BundlerHelper) do
  let(:gemfile_path) { File.join(__dir__, "fake_gemfile/Gemfile") }

  describe("#gemfile_dependencies") do
    subject(:gemfile_dependencies) { described_class.gemfile_dependencies(gemfile_path: gemfile_path) }

    # gemfile_dependencies repoints BUNDLE_GEMFILE at its argument, but Bundler
    # memoizes #definition — so without a reset first it returns whatever gemfile
    # was loaded earlier (still_active's own path-sourced definition when this spec
    # runs before anything else has reset Bundler). Reset before each example so the
    # fixture Gemfile is actually read, and restore BUNDLE_GEMFILE + reset after so
    # the fixture path doesn't leak into later specs.
    around do |example|
      original_gemfile = ENV.fetch("BUNDLE_GEMFILE", nil)
      Bundler.reset!
      example.run
    ensure
      ENV["BUNDLE_GEMFILE"] = original_gemfile
      Bundler.reset!
      Bundler.reset_settings_and_root! if Bundler.respond_to?(:reset_settings_and_root!)
    end

    context("when Bundler.definition.locked_gems is nil (no Gemfile.lock)") do
      let(:fake_definition) do
        instance_double(Bundler::Definition, dependencies: [], locked_gems: nil)
      end

      before do
        allow(Bundler).to(receive(:definition).and_return(fake_definition))
        allow(Bundler::SharedHelpers).to(receive(:set_env))
      end

      it("raises MissingLockfileError with the absolute path and a helpful message") do
        expect { described_class.gemfile_dependencies(gemfile_path: "Gemfile") }
          .to(raise_error(StillActive::MissingLockfileError) do |e|
            expect(e.message).to(include("run `bundle lock`"))
            expect(e.message).to(include(File.expand_path("Gemfile")))
          end)
      end
    end

    it("returns the versioned gems specified in the gemfile") do
      gem_names = gemfile_dependencies.map { |dep| dep[:name] }
      expect(gem_names).to(include("rake", "rspec"))
    end

    it("includes version strings for each dependency") do
      gemfile_dependencies.each do |dep|
        expect(dep).to(have_key(:name))
        expect(dep).to(have_key(:version))
        expect(dep[:version]).to(match(/\A\d+\.\d+/))
      end
    end

    it("includes source_type for each dependency") do
      gemfile_dependencies.each do |dep|
        expect(dep[:source_type]).to(eq(:rubygems))
      end
    end

    it("includes source_uri for each dependency") do
      gemfile_dependencies.each do |dep|
        expect(dep[:source_uri]).to(be_a(String))
      end
    end
  end

  describe(".detect_source_type") do
    it("returns :rubygems for Rubygems source") do
      spec = instance_double(Bundler::LazySpecification, source: Bundler::Source::Rubygems.new)
      expect(described_class.send(:detect_source_type, spec)).to(eq(:rubygems))
    end

    it("returns :git for Git source") do
      source = Bundler::Source::Git.new("uri" => "https://github.com/example/gem.git")
      spec = instance_double(Bundler::LazySpecification, source: source)
      expect(described_class.send(:detect_source_type, spec)).to(eq(:git))
    end

    it("returns :path for Path source") do
      source = Bundler::Source::Path.new("path" => "/tmp/my_gem")
      spec = instance_double(Bundler::LazySpecification, source: source)
      expect(described_class.send(:detect_source_type, spec)).to(eq(:path))
    end
  end
end
