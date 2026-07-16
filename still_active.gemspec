# frozen_string_literal: true

require_relative "lib/still_active/version"

Gem::Specification.new do |spec|
  spec.name          = "still_active"
  spec.version       = StillActive::VERSION
  spec.authors       = ["Sean Floyd"]
  spec.email         = ["contact@seanfloyd.dev"]

  spec.summary       = "Audit your dependencies for maintenance health, abandonment, and below-the-fix vulnerabilities. " \
    "Ruby gems natively; npm, PyPI, Cargo, Go, Maven, and NuGet via a CycloneDX SBOM."
  spec.description   = "Analyses your Gemfile.lock for dependency health across the full transitive graph: " \
    "whether each gem is actively maintained (last activity on GitHub, GitLab, or Codeberg/Forgejo, plus " \
    "release recency), outdated versions, archived repos, OpenSSF Scorecard scores, known vulnerabilities " \
    "(deps.dev and OSV, merged with ruby-advisory-db, flagging advisories with no fix and pins that sit below " \
    "the fix), poison-pill compatibility ceilings, and libyear drift. Ruby version freshness with EOL detection. " \
    "The same maintenance lens travels cross-ecosystem: point --sbom at a CycloneDX SBOM to assess npm, PyPI, " \
    "Cargo, Go, Maven, and NuGet packages via deps.dev and ecosyste.ms. " \
    "Handles rubygems, git, path, GitHub Packages, and JFrog Artifactory sources. " \
    "Outputs coloured terminal tables, markdown, JSON (with a versioned, contract-tested schema), " \
    "SARIF for GitHub code scanning, and a CycloneDX SBOM. " \
    "CI quality gates (--fail-if-critical / -warning / -vulnerable / -outdated / -poison / -language-ceiling) " \
    "with granular, committed suppression via .still_active.yml. " \
    "Complements bundle outdated, bundler-audit, and libyear-bundler by adding the maintenance signal they " \
    "don't, and folds their version, CVE, and libyear checks into one report."
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

  # 2.0/2.1 ship a scheduler that breaks our fan-out (io_read); 2.2 is the
  # verified floor (checked against Ruby 3.3 in Docker). octokit/faraday-retry/
  # gems work down to ancient versions, so they stay unpinned rather than
  # carry an artificial floor.
  spec.add_runtime_dependency("async", ">= 2.2")
  spec.add_runtime_dependency("bundler", ">= 2.0")
  # cvss-suite (CVSS v4.0 base-score from an OSV vector, for the CVSS-4-only advisory
  # deps.dev can't score) is an OPTIONAL dependency, NOT declared here: it exact-pins
  # bundler and caps bigdecimal, the poison-pill pattern still_active flags, so we
  # won't force it on users or trip our own audit. CvssHelper soft-requires it; absent,
  # the OSV/GHSA severity label still carries gating + level and the number is skipped.
  # Install cvss-suite (or run the distribution that bundles it) to light up the number.
  spec.add_runtime_dependency("faraday-retry")
  spec.add_runtime_dependency("gems")
  spec.add_runtime_dependency("octokit")
  # Spec-compliant package-URL parsing for SBOM ingestion (decodes npm scopes,
  # maven group:artifact, qualifiers). 0.1 is the verified floor; the official
  # package-url org gem (vetted via still_active itself: maintained, no advisories).
  spec.add_runtime_dependency("packageurl-ruby", ">= 0.1.0")
  # node-semver range satisfaction for the npm/cargo below-the-fix signal: deciding
  # whether a CVE's fixed version escapes a package's declared constraint needs
  # PATCH precision (their fixes are mostly same-major patch bumps), and hand-rolling
  # node-semver's prerelease + caret-on-0.x rules is the correctness minefield this
  # composes away. Vetted via still_active itself: maintained (2026 release), MIT,
  # zero runtime dependencies. cargo reuses it behind a bare-version->caret shim.
  spec.add_runtime_dependency("semantic_range", ">= 3.0")
end
