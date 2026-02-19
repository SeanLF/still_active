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
  end
end
