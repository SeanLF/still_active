# frozen_string_literal: true

RSpec.describe(StillActive::EcosystemLens) do
  # Reset the shared config singleton: repo_provider reads github_oauth_token to
  # choose GithubClient vs EcosystemsClient, and a prior spec (e.g. workflow_spec)
  # leaves a test token on the singleton. Without this, run order decides whether
  # the lens hits the (stubbed) ecosyste.ms path or the live GitHub API. Matches
  # the convention in config_spec/forgejo_client_spec.
  before do
    StillActive.reset
    # Poison-pill enrichment fires for any dormant package; default it to "no
    # declared deps" so existing dormant/archived fixtures stay network-free. The
    # poison-pill context overrides this per example.
    allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([]))
  end

  # Stub the deps.dev version endpoint (advisory keys + SOURCE_REPO link).
  def stub_version(advisory_keys: [], source_repo: nil)
    links = source_repo ? [{ "label" => "SOURCE_REPO", "url" => source_repo }] : []
    body = { "advisoryKeys" => advisory_keys.map { { "id" => _1 } }, "links" => links }
    stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/.+/versions/.+})
      .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: body.to_json)
  end

  # Stub the deps.dev package endpoint (the latest-release-date source). The
  # regex excludes the version sub-path so it never shadows stub_version.
  def stub_package(default_published_at:)
    versions = [{ "versionKey" => { "version" => "9.9.9" }, "isDefault" => true, "publishedAt" => default_published_at }]
    stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/[^/]+\z})
      .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: { "versions" => versions }.to_json)
  end

  def stub_project_scorecard(score: 7.0, maintained: 8)
    body = { "scorecard" => { "overallScore" => score, "date" => "2026-01-01", "checks" => [{ "name" => "Maintained", "score" => maintained }] } }
    stub_request(:get, %r{api\.deps\.dev/v3alpha/projects/})
      .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: body.to_json)
  end

  def stub_advisory(id:, cvss: 9.8)
    body = { "advisoryKey" => { "id" => id }, "title" => "boom", "aliases" => [], "cvss3Score" => cvss }
    stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/})
      .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: body.to_json)
  end

  def stub_ecosystems_repo(archived:, pushed_at: "2026-01-01T00:00:00Z")
    body = { "archived" => archived, "pushed_at" => pushed_at }
    stub_request(:get, %r{repos\.ecosyste\.ms/api/v1/hosts/GitHub/repositories/})
      .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: body.to_json)
  end

  describe(".assess") do
    it("assembles a gem_data hash an actively-maintained npm package reads as :ok") do
      stub_version(source_repo: "https://github.com/expressjs/express")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard(score: 6.5, maintained: 9)
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :npm, name: "express", version: "5.2.1")

      expect(result).to(include(
        ecosystem: :npm,
        name: "express",
        version_used: "5.2.1",
        latest_version_release_date: "2026-06-01T00:00:00Z",
        repository_url: "https://github.com/expressjs/express",
        archived: false,
        scorecard_score: 6.5,
        scorecard_maintained: 9,
        vulnerability_count: 0,
      ))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:ok))
    end

    it("reads a clean, long-dormant pypi package as :legacy") do
      stub_version(source_repo: "https://github.com/owner/sleepy")
      stub_package(default_published_at: "2018-01-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :pypi, name: "sleepy", version: "1.0.0")

      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:legacy))
    end

    it("surfaces a vulnerability at the locked version and counts it") do
      stub_version(advisory_keys: ["GHSA-xxxx"], source_repo: "https://github.com/owner/leaky")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_advisory(id: "GHSA-xxxx")
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :cargo, name: "leaky", version: "0.1.0")

      expect(result[:vulnerability_count]).to(eq(1))
      expect(result[:vulnerabilities].first).to(include(id: "GHSA-xxxx"))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:vulnerable))
    end

    it("reads an archived repo that still publishes recent releases as :stale, not dead") do
      stub_version(source_repo: "https://github.com/owner/moved")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: true)

      result = described_class.assess(ecosystem: :npm, name: "moved", version: "2.0.0")

      expect(result[:archived]).to(be(true))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:stale))
    end

    it("degrades a private/unresolvable package to all-nil signals -> :unknown") do
      # deps.dev 404s for a private package; ecosyste.ms is never reached because
      # there is no deps.dev-derived project to look up.
      stub_request(:get, /api\.deps\.dev/).to_return(status: 404)

      result = described_class.assess(ecosystem: :npm, name: "@acme/private", version: "1.0.0")

      expect(result).to(include(
        latest_version_release_date: nil,
        archived: nil,
        repository_url: nil,
        vulnerability_count: 0,
      ))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
    end

    it("does not look up repo signals for a non-github deps.dev project (gitlab archived unknown)") do
      stub_version(source_repo: "https://gitlab.com/group/proj")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      eco = stub_ecosystems_repo(archived: true)

      result = described_class.assess(ecosystem: :pypi, name: "proj", version: "1.0.0")

      expect(eco).not_to(have_been_requested)
      expect(result[:archived]).to(be_nil)
      expect(result[:repository_url]).to(eq("https://gitlab.com/group/proj"))
    end

    it("recovers archived from the package's default version when the locked version isn't indexed") do
      # Finding A: a yanked/normalization-mismatched locked version 404s on the
      # version endpoint, so its project link is gone. Without a fallback the repo
      # (and thus archived) vanishes and a fresh package date reads a false :ok.
      # The default version is still indexed, so its link recovers the repo.
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/[^/]+/versions/1\.0\.0})
        .to_return(status: 404)
      stub_package(default_published_at: "2026-06-01T00:00:00Z") # default version is "9.9.9"
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/[^/]+/versions/9\.9\.9})
        .to_return(status: 200,
          headers: { "Content-Type" => "application/json" },
          body: { "links" => [{ "label" => "SOURCE_REPO", "url" => "https://github.com/owner/archived" }] }.to_json)
      stub_project_scorecard
      stub_ecosystems_repo(archived: true)

      result = described_class.assess(ecosystem: :npm, name: "mismatch", version: "1.0.0")

      expect(result[:archived]).to(be(true))
      expect(result[:repository_url]).to(eq("https://github.com/owner/archived"))
      expect(StillActive::StatusHelper.gem_status(result)).not_to(eq(:ok))
    end

    it("still counts a known advisory key whose detail fetch fails (no silent under-report)") do
      # Finding B: version_info proves the package is vulnerable (two advisory
      # keys), but the advisory detail endpoint is down. The count must reflect
      # the keys, not the enriched details, or a known-vulnerable dep reads clean.
      stub_version(advisory_keys: ["GHSA-aaaa", "GHSA-bbbb"], source_repo: "https://github.com/owner/leaky")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/}).to_return(status: 503)
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :npm, name: "leaky", version: "0.1.0")

      expect(result[:vulnerability_count]).to(eq(2))
      expect(result[:vulnerabilities].map { _1[:id] }).to(contain_exactly("GHSA-aaaa", "GHSA-bbbb"))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:vulnerable))
    end

    it("does not split a nested gitlab project path into a bogus owner/name repo lookup") do
      stub_version(source_repo: "https://gitlab.com/group/subgroup/proj")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      eco = stub_ecosystems_repo(archived: true)

      result = described_class.assess(ecosystem: :pypi, name: "proj", version: "1.0.0")

      expect(eco).not_to(have_been_requested)
      expect(result[:archived]).to(be_nil)
    end
  end

  describe(".assess poison-pill (cross-ecosystem)") do
    before do
      stub_version(source_repo: "https://github.com/owner/pkg")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)
    end

    # Drive the package's own dormancy + each dep's latest through one mock, keyed
    # by name, so a dormant package and its below-latest dep are both expressible.
    def stub_latest(dates)
      allow(StillActive::DepsDevClient).to(receive(:default_version_info)) do |name:, **|
        entry = dates[name]
        entry.is_a?(Hash) ? entry : { version: "9.9.9", published_at: entry }
      end
    end

    it("flags a dormant pypi package that caps a runtime dep below its latest major (Flask -> Werkzeug)") do
      stub_latest("flask" => "2016-05-01T00:00:00Z", "Werkzeug" => { version: "3.1.3" })
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies))
        .with(name: "flask", version: "0.12.5", registry: "pypi.org")
        .and_return([{ package_name: "Werkzeug", requirements: "<1.0,>=0.7" }])

      result = described_class.assess(ecosystem: :pypi, name: "flask", version: "0.12.5")

      expect(result[:poison]).to(be(true))
      expect(result[:constraints]).to(eq([
        { dependency: "Werkzeug", requirement: "<1.0,>=0.7", dep_latest: "3.1.3", majors_behind: 3, kind: :ceiling },
      ]))
    end

    it("surfaces a dormant pypi package's below-latest exact-pin as a hazard, not poison (celery-style vine ==)") do
      stub_latest("celery" => "2017-01-01T00:00:00Z", "vine" => { version: "5.1.0" })
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies)).and_return([
        { package_name: "vine", requirements: "==1.3.0" },
      ])

      result = described_class.assess(ecosystem: :pypi, name: "celery", version: "4.0.0")

      expect(result[:poison]).to(be(false))
      expect(result[:constraints]).to(eq([
        { dependency: "vine", requirement: "==1.3.0", dep_latest: "5.1.0", majors_behind: 4, kind: :exact_pin },
      ]))
    end

    it("suppresses poison on subtree-local ecosystems (npm/cargo): a transitive cap pins a duplicate copy, it does not hold the tree hostage") do
      # npm nests versions and cargo coexists majors, so a below-latest cap is
      # subtree-local, not a tree-wide block; the blocking case (peerDependencies)
      # isn't visible in ecosyste.ms data. Suppress rather than over-claim.
      stub_latest("oldpkg" => "2017-01-01T00:00:00Z")
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies))

      [:npm, :cargo].each do |eco|
        result = described_class.assess(ecosystem: eco, name: "oldpkg", version: "1.0.0")
        expect(result).not_to(have_key(:poison))
        expect(result).not_to(have_key(:constraints))
      end
      expect(StillActive::EcosystemsClient).not_to(have_received(:declared_dependencies))
    end

    it("does NOT flag a maintained (flat-ecosystem) package's cap, and never asks for its constraints") do
      stub_latest("fresh" => "2026-05-01T00:00:00Z")
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies))

      result = described_class.assess(ecosystem: :pypi, name: "fresh", version: "1.0.0")

      expect(result).not_to(have_key(:poison))
      expect(StillActive::EcosystemsClient).not_to(have_received(:declared_dependencies))
    end

    it("re-attempts a capped dep's latest across packages rather than caching a transient nil (no run-wide pill suppression)") do
      # A shared cache across two dormant packages that both cap Werkzeug: the
      # first hits a momentary deps.dev nil on Werkzeug; the second must still
      # resolve it, not read a cached miss.
      cache = {}
      werkzeug_calls = 0
      allow(StillActive::DepsDevClient).to(receive(:default_version_info)) do |name:, **|
        if name == "Werkzeug"
          werkzeug_calls += 1
          werkzeug_calls == 1 ? nil : { version: "3.1.3" }
        else
          { version: "9.9.9", published_at: "2016-05-01T00:00:00Z" } # dormant package
        end
      end
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies)).and_return([
        { package_name: "Werkzeug", requirements: "<1.0,>=0.7" },
      ])

      first = described_class.assess(ecosystem: :pypi, name: "flask", version: "0.12.5", constraint_cache: cache)
      second = described_class.assess(ecosystem: :pypi, name: "flask2", version: "0.12.5", constraint_cache: cache)

      expect(first).not_to(have_key(:constraints)) # transient nil -> dropped this time
      expect(second[:poison]).to(be(true))         # but recovered for the next package
    end

    it("does not attempt constraints for an unmapped ecosystem (maven/go/nuget)") do
      stub_latest("dormant.artifact" => "2015-01-01T00:00:00Z")
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies))

      result = described_class.assess(ecosystem: :maven, name: "dormant.artifact", version: "1.0.0")

      expect(result).not_to(have_key(:constraints))
      expect(StillActive::EcosystemsClient).not_to(have_received(:declared_dependencies))
    end
  end

  describe(".assess language ceiling (Python)") do
    # Python support window fixture: 3.14/3.10 supported, 3.9/3.8 EOL, latest
    # stable 3.14.6 (not fresh). Mirrors the live endoflife.date shape.
    let(:python_range) do
      {
        oldest_supported: Gem::Version.new("3.10"),
        latest_stable: Gem::Version.new("3.14.6"),
        latest_stable_fresh: false,
        cycles: [
          { version: Gem::Version.new("3.14"), eol: false, eol_date: Time.parse("2030-10-31") },
          { version: Gem::Version.new("3.10"), eol: false, eol_date: Time.parse("2026-10-31") },
          { version: Gem::Version.new("3.9"), eol: true, eol_date: Time.parse("2025-10-31") },
          { version: Gem::Version.new("3.8"), eol: true, eol_date: Time.parse("2024-10-14") },
        ],
      }
    end

    before do
      # deps.dev default version 9.9.9 is the "latest" for the fixed_by_upgrade probe.
      stub_version(source_repo: "https://github.com/numba/numba")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)
    end

    it("flags an EOL-forcing requires_python cap as a critical Python ceiling, noting the gem upgrade lifts it") do
      allow(StillActive::PypiClient).to(receive(:requires_python).with(name: "numba", version: "0.53.1").and_return(">=3.6,<3.10"))
      allow(StillActive::PypiClient).to(receive(:requires_python).with(name: "numba", version: "9.9.9").and_return(">=3.10"))

      result = described_class.assess(ecosystem: :pypi, name: "numba", version: "0.53.1", python_range: python_range)

      ceiling = result[:language_ceiling]
      expect(ceiling[:runtime]).to(eq("Python"))
      expect(ceiling[:eol_forced]).to(be(true))
      expect(ceiling[:severity]).to(eq(:critical))
      expect(ceiling[:ceiling_version]).to(eq("3.9"))
      expect(ceiling[:fixed_by_upgrade]).to(be(true))
    end

    it("does not claim fixed_by_upgrade when the latest version's requires_python can't be read (no over-claim on a failed fetch)") do
      # PypiClient returns nil for BOTH "declares nothing" and "fetch failed"; the
      # ceiling must not advise an upgrade it couldn't positively verify.
      allow(StillActive::PypiClient).to(receive(:requires_python).with(name: "numba", version: "0.53.1").and_return(">=3.6,<3.10"))
      allow(StillActive::PypiClient).to(receive(:requires_python).with(name: "numba", version: "9.9.9").and_return(nil))

      result = described_class.assess(ecosystem: :pypi, name: "numba", version: "0.53.1", python_range: python_range)

      ceiling = result[:language_ceiling]
      expect(ceiling[:eol_forced]).to(be(true))
      expect(ceiling[:fixed_by_upgrade]).to(be(false))
    end

    it("flags a cap below the latest stable (but on a supported Python) as a note") do
      allow(StillActive::PypiClient).to(receive(:requires_python).and_return(">=3.8,<3.13"))

      result = described_class.assess(ecosystem: :pypi, name: "scipy", version: "1.7.3", python_range: python_range)

      ceiling = result[:language_ceiling]
      expect(ceiling[:runtime]).to(eq("Python"))
      expect(ceiling[:eol_forced]).to(be(false))
      expect(ceiling[:severity]).to(eq(:note))
    end

    it("does not flag a pure floor requires_python (a floor is not a ceiling)") do
      allow(StillActive::PypiClient).to(receive(:requires_python).and_return(">=3.8"))

      result = described_class.assess(ecosystem: :pypi, name: "numpy", version: "1.21.0", python_range: python_range)

      expect(result).not_to(have_key(:language_ceiling))
    end

    it("does not flag when the package declares no requires_python") do
      allow(StillActive::PypiClient).to(receive(:requires_python).and_return(nil))

      result = described_class.assess(ecosystem: :pypi, name: "loose", version: "1.0.0", python_range: python_range)

      expect(result).not_to(have_key(:language_ceiling))
    end

    it("does not read requires_python for a non-Python ecosystem, even with a window") do
      allow(StillActive::PypiClient).to(receive(:requires_python))

      result = described_class.assess(ecosystem: :npm, name: "express", version: "5.2.1", python_range: python_range)

      expect(result).not_to(have_key(:language_ceiling))
      expect(StillActive::PypiClient).not_to(have_received(:requires_python))
    end

    it("does nothing when the Python support window is unavailable (nil range)") do
      allow(StillActive::PypiClient).to(receive(:requires_python))

      result = described_class.assess(ecosystem: :pypi, name: "numba", version: "0.53.1", python_range: nil)

      expect(result).not_to(have_key(:language_ceiling))
      expect(StillActive::PypiClient).not_to(have_received(:requires_python))
    end
  end
end
