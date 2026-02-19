# frozen_string_literal: true

require_relative "lib/still_active/version"

Gem::Specification.new do |spec|
  spec.name          = "still_active"
  spec.version       = StillActive::VERSION
  spec.authors       = ["Sean Floyd"]
  spec.email         = ["contact@seanfloyd.dev"]

  spec.summary       = "Check if your Ruby dependencies are still actively maintained."
  spec.description   = "Analyses your Gemfile dependencies for staleness: latest releases, " \
    "last commit dates (GitHub and GitLab), OpenSSF Scorecard scores, " \
    "and known vulnerabilities via deps.dev. " \
    "Outputs coloured terminal tables, markdown, or JSON with CI gating support."
  spec.homepage      = "https://github.com/SeanLF/still_active"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    %x(git ls-files -z).split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{\Abin/still_active}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency("debug")
  spec.add_development_dependency("faker")
  spec.add_development_dependency("rubocop")
  spec.add_development_dependency("rubocop-performance")
  spec.add_development_dependency("rubocop-rspec")
  spec.add_development_dependency("rubocop-shopify")

  spec.add_runtime_dependency("async")
  spec.add_runtime_dependency("bundler", ">= 2.0")
  spec.add_runtime_dependency("faraday-retry")
  spec.add_runtime_dependency("gems")
  spec.add_runtime_dependency("octokit")
end
