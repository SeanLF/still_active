# frozen_string_literal: true

RSpec.describe(StillActive::BundlerHelper) do
  let(:gemfile_path) { File.join(__dir__, "fake_gemfile/Gemfile") }

  describe("#gemfile_dependencies") do
    subject { described_class.gemfile_dependencies(gemfile_path: gemfile_path) }
    let(:expected_results) do
      [
        { name: "rake", version: "13.0.6" },
        { name: "rspec", version: "3.10.0" },
      ]
    end
    after { Bundler.reset_settings_and_root! }

    it("returns the versioned gems specified in the gemfile") do
      expected_results.each { |expected_result| expect(subject).to(include(expected_result)) }
    end
  end
end
