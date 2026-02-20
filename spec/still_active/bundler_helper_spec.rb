# frozen_string_literal: true

RSpec.describe(StillActive::BundlerHelper) do
  let(:gemfile_path) { File.join(__dir__, "fake_gemfile/Gemfile") }

  describe("#gemfile_dependencies") do
    subject(:gemfile_dependencies) { described_class.gemfile_dependencies(gemfile_path: gemfile_path) }

    after do
      Bundler.reset!
      Bundler.reset_settings_and_root! if Bundler.respond_to?(:reset_settings_and_root!)
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
