# frozen_string_literal: true

require_relative "lib/still_active/version"

Gem::Specification.new do |spec|
  spec.name          = "still_active"
  spec.version       = StillActive::VERSION
  spec.authors       = ["Sean Floyd"]
  spec.email         = ["contact@seanfloyd.dev"]

  spec.summary       = "Audit your Ruby dependencies for maintenance health, outdated versions, vulnerabilities, and abandoned gems."
  spec.description   = "Analyses your Gemfile.lock for dependency health across the full transitive graph: " \
    "whether each gem is actively maintained (last activity on GitHub, GitLab, or Codeberg/Forgejo, plus " \
    "release recency), outdated versions, archived repos, OpenSSF Scorecard scores, known vulnerabilities " \
    "(deps.dev merged with ruby-advisory-db), and libyear drift. Ruby version freshness with EOL detection. " \
    "Handles rubygems, git, path, GitHub Packages, and JFrog Artifactory sources. " \
    "Outputs coloured terminal tables, markdown, JSON (with a versioned, contract-tested schema), " \
    "SARIF for GitHub code scanning, and a CycloneDX SBOM. " \
    "CI quality gates (--fail-if-critical / -warning / -vulnerable / -outdated) with granular, committed " \
    "suppression via .still_active.yml. " \
    "A comprehensive alternative to running bundle outdated, bundler-audit, and libyear-bundler separately."
  spec.homepage      = "https://github.com/SeanLF/still_active"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.3.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["documentation_uri"] = "#{spec.homepage}#readme"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    %x(git ls-files -z).split("\x0").select do |f|
      f.start_with?("lib/", "bin/still_active") || f.match?(/\A(LICENSE|README|CHANGELOG|still_active\.gemspec)\b/)
    end
  end
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{\Abin/still_active}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency("bundler-audit")
  spec.add_development_dependency("debug")
  spec.add_development_dependency("faker")
  spec.add_development_dependency("json_schemer")
  spec.add_development_dependency("rubocop")
  spec.add_development_dependency("rubocop-performance")
  spec.add_development_dependency("rubocop-rspec")
  spec.add_development_dependency("rubocop-shopify")

  # 2.0/2.1 ship a scheduler that breaks our fan-out (io_read); 2.2 is the
  # verified floor (checked against Ruby 3.3 in Docker). octokit/faraday-retry/
  # gems work down to ancient versions, so they stay unpinned rather than
  # carry an artificial floor.
  spec.add_runtime_dependency("async", ">= 2.2")
  spec.add_runtime_dependency("bundler", ">= 2.0")
  # CVSS v4.0 base-score computation from an OSV advisory's vector string: deps.dev
  # stores only CVSS 3.x, so a CVSS-4-only advisory has no numeric score (the flagship
  # protobuf case). MIT, one dep (bigdecimal), a real MacroVector implementation vetted
  # against FIRST's calculator. 4.1 is the floor (the rounding fixes landed there).
  spec.add_runtime_dependency("cvss-suite", ">= 4.1")
  spec.add_runtime_dependency("faraday-retry")
  spec.add_runtime_dependency("gems")
  spec.add_runtime_dependency("octokit")
  # Spec-compliant package-URL parsing for SBOM ingestion (decodes npm scopes,
  # maven group:artifact, qualifiers). 0.1 is the verified floor; the official
  # package-url org gem (vetted via still_active itself: maintained, no advisories).
  spec.add_runtime_dependency("packageurl-ruby", ">= 0.1.0")
end
