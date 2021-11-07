# frozen_string_literal: true

require_relative "lib/still_active/version"

Gem::Specification.new do |spec|
  spec.name          = "still_active"
  spec.version       = StillActive::VERSION
  spec.authors       = ["Sean Floyd"]
  spec.email         = ["contact@seanfloyd.dev"]

  spec.summary       = "Check if gems are under active development."
  spec.description   = "Obtain last release, pre-release, and last commit date to determine if a gem is still under active development."
  spec.homepage      = "https://github.com/SeanLF/still_active."
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.4.0"

  # spec.metadata["allowed_push_host"] = "TODO: Set to 'https://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.metadata["source_code_uri"]}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    %x(git ls-files -z).split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{\Abin/still_active}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # For more information and examples about making a new gem, checkout our
  # guide at: https://bundler.io/guides/creating_gem.html
  spec.add_development_dependency("debug")
  spec.add_development_dependency("rubocop")
  spec.add_development_dependency("rubocop-shopify")

  spec.add_runtime_dependency("async")
  # spec.add_runtime_dependency("cli-ui")
  # spec.add_runtime_dependency("async-http")
  spec.add_runtime_dependency("gems")
  spec.add_runtime_dependency("github_api")
  # spec.add_runtime_dependency("gitlab")
  # spec.add_runtime_dependency("tty-progressbar")
end
