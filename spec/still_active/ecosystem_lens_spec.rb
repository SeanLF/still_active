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

  # Stub the deps.dev version endpoint (advisory keys + SOURCE_REPO link + the
  # locked version's publishedAt, the libyear input).
  def stub_version(advisory_keys: [], source_repo: nil, published_at: nil, licenses: nil)
    links = source_repo ? [{"label" => "SOURCE_REPO", "url" => source_repo}] : []
    body = {"advisoryKeys" => advisory_keys.map { {"id" => _1} }, "links" => links, "publishedAt" => published_at}
    body["licenses"] = licenses if licenses
    stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/.+/versions/.+})
      .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: body.to_json)
  end

  # Stub the deps.dev package endpoint (the latest-release-date source). The
  # regex excludes the version sub-path so it never shadows stub_version.
  def stub_package(default_published_at:)
    versions = [{"versionKey" => {"version" => "9.9.9"}, "isDefault" => true, "publishedAt" => default_published_at}]
    stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/[^/]+\z})
      .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: {"versions" => versions}.to_json)
  end

  def stub_project_scorecard(score: 7.0, maintained: 8)
    body = {"scorecard" => {"overallScore" => score, "date" => "2026-01-01", "checks" => [{"name" => "Maintained", "score" => maintained}]}}
    stub_request(:get, %r{api\.deps\.dev/v3alpha/projects/})
      .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: body.to_json)
  end

  def stub_advisory(id:, cvss: 9.8)
    body = {"advisoryKey" => {"id" => id}, "title" => "boom", "aliases" => [], "cvss3Score" => cvss}
    stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/})
      .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: body.to_json)
  end

  def stub_ecosystems_repo(archived:, pushed_at: "2026-01-01T00:00:00Z")
    body = {"archived" => archived, "pushed_at" => pushed_at}
    stub_request(:get, %r{repos\.ecosyste\.ms/api/v1/hosts/GitHub/repositories/})
      .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: body.to_json)
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
        vulnerability_count: 0
      ))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:ok))
    end

    it("carries the licence (parity with the native path's license)") do
      stub_version(source_repo: "https://github.com/expressjs/express", licenses: ["MIT"])
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :npm, name: "express", version: "5.2.1")

      expect(result[:license]).to(eq("MIT"))
    end

    it("reads a licence the pinned version declares as an SPDX expression") do
      stub_version(source_repo: "https://github.com/serde-rs/serde", licenses: ["Apache-2.0 OR MIT"])
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :cargo, name: "serde", version: "1.0.190")

      expect(result[:license]).to(eq("Apache-2.0 OR MIT"))
    end

    it("leaves the licence nil when deps.dev serves none, rather than an empty string") do
      stub_version(source_repo: "https://github.com/expressjs/express")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :npm, name: "express", version: "5.2.1")

      expect(result).to(have_key(:license))
      expect(result[:license]).to(be_nil)
    end

    it("carries the latest stable version string (parity with the native path's latest_version)") do
      stub_version(source_repo: "https://github.com/owner/pkg")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :npm, name: "pkg", version: "1.0.0")

      # The formatters (terminal/markdown/SARIF) read :latest_version to show the
      # "behind X"/up-to-date delta; without it a cross-ecosystem audit can't.
      expect(result[:latest_version]).to(eq("9.9.9"))
    end

    it("computes libyear from the locked and latest release dates (cross-ecosystem parity with the native path)") do
      stub_version(source_repo: "https://github.com/psf/requests", published_at: "2023-05-22T15:12:42Z")
      stub_package(default_published_at: "2026-05-22T15:12:42Z") # 3 years newer
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :pypi, name: "requests", version: "2.31.0")

      expect(result[:version_used_release_date]).to(eq("2023-05-22T15:12:42Z"))
      expect(result[:libyear]).to(be_within(0.1).of(3.0))
    end

    it("leaves libyear nil when the locked version's release date is unavailable, rather than guessing") do
      stub_version(source_repo: "https://github.com/psf/requests") # no publishedAt
      stub_package(default_published_at: "2026-05-22T15:12:42Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :pypi, name: "requests", version: "2.31.0")

      expect(result[:libyear]).to(be_nil)
    end

    it("reads a clean, long-dormant pypi package as :legacy") do
      stub_version(source_repo: "https://github.com/owner/sleepy")
      stub_package(default_published_at: "2018-01-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :pypi, name: "sleepy", version: "1.0.0")

      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:legacy))
    end

    it("flags a pinned version deps.dev can't resolve, so a nonexistent version reads :unknown not :ok") do
      # The version endpoint 404s (version doesn't exist) but the package endpoint
      # resolves (fresh package). Without the flag, package-level health would report
      # this nonexistent version as :ok -- a confident wrong answer.
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/.+/versions/.+}).to_return(status: 404)
      stub_package(default_published_at: "2026-05-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      result = described_class.assess(ecosystem: :pypi, name: "requests", version: "999.999.999")

      expect(result[:version_unresolved]).to(be(true))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
    end

    it("reports up_to_date via a >= comparison, so a prerelease/ahead-of-stable pin reads current, not behind") do
      stub_version(source_repo: "https://github.com/owner/pkg")
      stub_package(default_published_at: "2026-05-01T00:00:00Z") # latest stable 9.9.9
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)
      assess = ->(v) { described_class.assess(ecosystem: :npm, name: "pkg", version: v) }

      expect(assess.call("9.9.9")[:up_to_date]).to(be(true))   # exactly latest stable
      expect(assess.call("1.0.0")[:up_to_date]).to(be(false))  # genuinely behind
      expect(assess.call("10.0.0")[:up_to_date]).to(be(true))  # ahead of stable
      expect(assess.call("10.0.0-canary.7")[:up_to_date]).to(be(true))  # prerelease of a higher major
      expect(assess.call("9.9.9-beta.1")[:up_to_date]).to(be(false))    # prerelease BEFORE the stable
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

    it("enriches a CVSS-4-only advisory (deps.dev score 0) with OSV's HIGH label and fixed versions") do
      # deps.dev stores only CVSS 3.x, so this advisory arrives unscored (cvss3Score 0).
      # OSV's GHSA label rescues the real HIGH and supplies the fixed ranges the
      # below-the-fix signal needs -- the CVSS-4 deflation, end to end.
      stub_version(advisory_keys: ["GHSA-cvss4"], source_repo: "https://github.com/protocolbuffers/protobuf")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_advisory(id: "GHSA-cvss4", cvss: 0)
      stub_ecosystems_repo(archived: false)
      stub_request(:get, "https://api.osv.dev/v1/vulns/GHSA-cvss4").to_return(
        status: 200,
        headers: {"Content-Type" => "application/json"},
        body: {
          "database_specific" => {"severity" => "HIGH"},
          "affected" => [{
            "package" => {"name" => "protobuf", "ecosystem" => "PyPI"},
            "ranges" => [{"type" => "ECOSYSTEM", "events" => [{"introduced" => "0"}, {"fixed" => "5.29.6"}]}]
          }]
        }.to_json
      )

      result = described_class.assess(ecosystem: :pypi, name: "protobuf", version: "4.21.6")

      vuln = result[:vulnerabilities].first
      expect(vuln).to(include(osv_severity: "HIGH", fixed_versions: ["5.29.6"]))
      expect(StillActive::VulnerabilityHelper.highest_severity(result[:vulnerabilities])).to(eq("high"))
      # Without OSV this advisory (deps.dev cvss3Score 0) would be unscored and fail closed.
      expect(StillActive::VulnerabilityHelper.unknown_severity?(vuln)).to(be(false))
    end

    it("drops a deps.dev advisory that OSV says does not affect the locked version") do
      # deps.dev lags an advisory amended with backport fixes, so a version patched on
      # an older line still carries the key (live: npm brace-expansion 1.1.18, patched
      # by the 1.1.17 branch the amendment added). OSV's /v1/query reflects the
      # amendment, and the package must come back clean rather than :vulnerable.
      stub_version(advisory_keys: ["GHSA-mh99-v99m-4gvg"], source_repo: "https://github.com/juliangruber/brace-expansion")
      stub_package(default_published_at: "2026-07-30T10:00:32Z")
      stub_project_scorecard
      stub_advisory(id: "GHSA-mh99-v99m-4gvg")
      stub_ecosystems_repo(archived: false)
      stub_request(:get, "https://api.osv.dev/v1/vulns/GHSA-mh99-v99m-4gvg").to_return(
        status: 200,
        headers: {"Content-Type" => "application/json"},
        body: {
          "database_specific" => {"severity" => "HIGH"},
          "affected" => [{
            "package" => {"name" => "brace-expansion", "ecosystem" => "npm"},
            "ranges" => [{"type" => "SEMVER", "events" => [{"introduced" => "0"}, {"fixed" => "1.1.17"}]}]
          }]
        }.to_json
      )
      stub_request(:post, "https://api.osv.dev/v1/query")
        .with(body: {version: "1.1.18", package: {name: "brace-expansion", ecosystem: "npm"}}.to_json)
        .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: "{}")

      result = described_class.assess(ecosystem: :npm, name: "brace-expansion", version: "1.1.18")

      expect(result[:vulnerability_count]).to(eq(0))
      expect(result[:vulnerabilities]).to(be_empty)
      expect(StillActive::StatusHelper.gem_status(result)).not_to(eq(:vulnerable))
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
        vulnerability_count: 0
      ))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
    end

    # The SBOM path used to read only github.com repositories; a GitLab project
    # got no archived signal at all.
    it("reads a GitLab project's archived state from GitLab, and says so") do
      stub_version(source_repo: "https://gitlab.com/group/proj")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_request(:get, "https://gitlab.com/api/v4/projects/group%2Fproj")
        .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: {archived: true, last_activity_at: "2026-01-01T00:00:00Z"}.to_json)

      result = described_class.assess(ecosystem: :pypi, name: "proj", version: "1.0.0")

      expect(result).to(include(archived: true, repository_source: "gitlab", repository_url: "https://gitlab.com/group/proj"))
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
          headers: {"Content-Type" => "application/json"},
          body: {"advisoryKeys" => [], "links" => [{"label" => "SOURCE_REPO", "url" => "https://github.com/owner/archived"}]}.to_json)
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

    it("looks a nested GitLab project up by its full path, not a bogus owner/name") do
      stub_version(source_repo: "https://gitlab.com/group/subgroup/proj")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      gitlab = stub_request(:get, "https://gitlab.com/api/v4/projects/group%2Fsubgroup%2Fproj")
        .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: {archived: false}.to_json)

      result = described_class.assess(ecosystem: :pypi, name: "proj", version: "1.0.0")

      expect(gitlab).to(have_been_requested)
      expect(result).to(include(archived: false, repository_source: "gitlab"))
    end
  end

  # A failed advisory lookup is "unchecked", never "clean"; a 404 is deps.dev
  # answering that it has no record, which is not a failure.
  # Go deprecates a module, not a version: a `// Deprecated:` comment in the
  # latest go.mod covers every version, but deps.dev only flags the version
  # whose go.mod carries it.
  describe(".assess Go module deprecation") do
    def version_record(deprecated:, reason: "")
      {status: 200, headers: {"Content-Type" => "application/json"},
       body: {"advisoryKeys" => [], "isDeprecated" => deprecated, "deprecatedReason" => reason}.to_json}
    end

    before do
      stub_project_scorecard
      stub_request(:get, %r{repos\.ecosyste\.ms/}).to_return(status: 404)
      stub_request(:get, %r{api\.github\.com/}).to_return(status: 404)
    end

    it("reads the module's deprecation from its latest version when an older one is pinned") do
      stub_package(default_published_at: "2024-03-01T00:00:00Z") # default version is "9.9.9"
      stub_request(:get, %r{/versions/v1\.3\.5\z}).to_return(version_record(deprecated: false))
      stub_request(:get, %r{/versions/9\.9\.9\z}).to_return(version_record(deprecated: true, reason: "Module deprecated: Use google.golang.org/protobuf instead."))

      result = described_class.assess(ecosystem: :go, name: "github.com/golang/protobuf", version: "v1.3.5")

      expect(result).to(include(deprecated: true, deprecation_reason: "Module deprecated: Use google.golang.org/protobuf instead."))
    end

    it("keeps npm's per-version deprecation per version") do
      stub_package(default_published_at: "2024-03-01T00:00:00Z")
      stub_request(:get, %r{/versions/1\.0\.0\z}).to_return(version_record(deprecated: false))
      stub_request(:get, %r{/versions/9\.9\.9\z}).to_return(version_record(deprecated: true, reason: "gone"))

      result = described_class.assess(ecosystem: :npm, name: "left-pad", version: "1.0.0")

      expect(result).to(include(deprecated: false, deprecation_reason: nil))
    end
  end

  describe(".assess repository coverage") do
    it("marks the repository unavailable when no source can read it, and the status unknown") do
      stub_version(source_repo: "https://github.com/expressjs/express")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_request(:get, %r{repos\.ecosyste\.ms/}).to_return(status: 503)
      stub_request(:get, "https://api.github.com/repos/expressjs/express").to_return(status: 503)

      result = nil
      expect { result = described_class.assess(ecosystem: :npm, name: "express", version: "5.2.1") }.to(output(/archived status unknown/).to_stderr)

      expect(result).to(include(repository_check: "failed", archived: nil))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
    end

    # Anonymous GitHub 404s a private repository too, so neither service knowing
    # it is unknown, not "not archived"; and a rerun won't change that.
    it("reads a repository neither ecosyste.ms nor GitHub knows as unknowable") do
      stub_version(source_repo: "https://github.com/gone/gone")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_request(:get, %r{repos\.ecosyste\.ms/}).to_return(status: 404)
      stub_request(:get, "https://api.github.com/repos/gone/gone").to_return(status: 404)

      result = described_class.assess(ecosystem: :npm, name: "gone", version: "1.0.0")
      expect(result).to(include(repository_check: "unknowable"))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
    end

    # Without a token, ecosyste.ms is asked first; one it hasn't crawled used to
    # read as "not archived". GitHub answers for a public repo without a token.
    it("asks GitHub when ecosyste.ms hasn't crawled the repository") do
      stub_version(source_repo: "https://github.com/owner/uncrawled")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_request(:get, %r{repos\.ecosyste\.ms/}).to_return(status: 404)
      stub_request(:get, "https://api.github.com/repos/owner/uncrawled")
        .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: {archived: true, pushed_at: "2025-01-01T00:00:00Z"}.to_json)

      result = described_class.assess(ecosystem: :npm, name: "uncrawled", version: "1.0.0")

      expect(result).to(include(archived: true, repository_source: "github"))
      expect(StillActive::StatusHelper.gem_status(result)).not_to(eq(:ok))
    end
  end

  describe(".assess advisory coverage") do
    it("marks the advisories unchecked, and the status unknown, when deps.dev can't answer the version") do
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/.+/versions/.+}).to_return(status: 503)
      stub_package(default_published_at: "2026-06-01T00:00:00Z")

      result = nil
      expect { result = described_class.assess(ecosystem: :npm, name: "express", version: "5.2.1") }.to(output(/503/).to_stderr)

      expect(result).to(include(vulnerabilities_checked: false, vulnerability_count: 0))
      expect(result).not_to(have_key(:version_unresolved))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
    end

    it("keeps a package deps.dev doesn't index checked (a private package has no public advisories)") do
      stub_request(:get, /api\.deps\.dev/).to_return(status: 404)

      result = described_class.assess(ecosystem: :npm, name: "@acme/internal", version: "1.0.0")

      expect(result).to(include(vulnerabilities_checked: true))
    end

    it("reports a checked version as checked") do
      stub_version(source_repo: "https://github.com/expressjs/express")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)

      expect(described_class.assess(ecosystem: :npm, name: "express", version: "5.2.1")).to(include(vulnerabilities_checked: true))
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
        entry.is_a?(Hash) ? entry : {version: "9.9.9", published_at: entry}
      end
    end

    it("flags a dormant pypi package that caps a runtime dep below its latest major (Flask -> Werkzeug)") do
      stub_latest("flask" => "2016-05-01T00:00:00Z", "Werkzeug" => {version: "3.1.3"})
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies))
        .with(name: "flask", version: "0.12.5", registry: "pypi.org")
        .and_return([{package_name: "Werkzeug", requirements: "<1.0,>=0.7"}])

      result = described_class.assess(ecosystem: :pypi, name: "flask", version: "0.12.5")

      expect(result[:poison]).to(be(true))
      expect(result[:constraints]).to(eq([
        {dependency: "Werkzeug", requirement: "<1.0,>=0.7", dep_latest: "3.1.3", majors_behind: 3, kind: :ceiling}
      ]))
    end

    it("surfaces a dormant pypi package's below-latest exact-pin as a hazard, not poison (celery-style vine ==)") do
      stub_latest("celery" => "2017-01-01T00:00:00Z", "vine" => {version: "5.1.0"})
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies)).and_return([
        {package_name: "vine", requirements: "==1.3.0"}
      ])

      result = described_class.assess(ecosystem: :pypi, name: "celery", version: "4.0.0")

      expect(result[:poison]).to(be(false))
      expect(result[:constraints]).to(eq([
        {dependency: "vine", requirement: "==1.3.0", dep_latest: "5.1.0", majors_behind: 4, kind: :exact_pin}
      ]))
    end

    it("keeps a dormant npm/cargo package's declared deps as security CANDIDATES, not rendered poison") do
      # npm nests versions and cargo coexists majors, so the pure below-latest cap is
      # subtree-local noise (caret is the default): the `poison`/`constraints` signal
      # stays suppressed. But we keep every declared dep as a `capped_deps` CANDIDATE
      # for the security below-the-fix path -- the correlator alone sees the tree's
      # resolved versions + advisories and promotes only the ones pinning a vulnerable
      # copy below its fix. No dep_latest fetch here: the wall test is patch-precise.
      stub_latest("oldpkg" => "2017-01-01T00:00:00Z")
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies))
        .and_return([{package_name: "vulndep", requirements: "^1.2.0"}])

      [:npm, :cargo].each do |eco|
        result = described_class.assess(ecosystem: eco, name: "oldpkg", version: "1.0.0")
        expect(result).not_to(have_key(:poison))
        expect(result).not_to(have_key(:constraints))
        expect(result[:capped_deps]).to(eq([{dependency: "vulndep", requirement: "^1.2.0"}]))
      end
    end

    it("does not fetch or attach candidates for a MAINTAINED npm package (dormancy-gated)") do
      stub_latest("fresh" => "2026-05-01T00:00:00Z")
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies))

      result = described_class.assess(ecosystem: :npm, name: "fresh", version: "1.0.0")

      expect(result).not_to(have_key(:capped_deps))
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
          (werkzeug_calls == 1) ? nil : {version: "3.1.3"}
        else
          {version: "9.9.9", published_at: "2016-05-01T00:00:00Z"} # dormant package
        end
      end
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies)).and_return([
        {package_name: "Werkzeug", requirements: "<1.0,>=0.7"}
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
          {version: Gem::Version.new("3.14"), eol: false, eol_date: Time.parse("2030-10-31")},
          {version: Gem::Version.new("3.10"), eol: false, eol_date: Time.parse("2026-10-31")},
          {version: Gem::Version.new("3.9"), eol: true, eol_date: Time.parse("2025-10-31")},
          {version: Gem::Version.new("3.8"), eol: true, eol_date: Time.parse("2024-10-14")}
        ]
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

      result = described_class.assess(ecosystem: :pypi, name: "numba", version: "0.53.1", runtime_ranges: {python: python_range})

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

      result = described_class.assess(ecosystem: :pypi, name: "numba", version: "0.53.1", runtime_ranges: {python: python_range})

      ceiling = result[:language_ceiling]
      expect(ceiling[:eol_forced]).to(be(true))
      expect(ceiling[:fixed_by_upgrade]).to(be(false))
    end

    it("flags a cap below the latest stable (but on a supported Python) as a note") do
      allow(StillActive::PypiClient).to(receive(:requires_python).and_return(">=3.8,<3.13"))

      result = described_class.assess(ecosystem: :pypi, name: "scipy", version: "1.7.3", runtime_ranges: {python: python_range})

      ceiling = result[:language_ceiling]
      expect(ceiling[:runtime]).to(eq("Python"))
      expect(ceiling[:eol_forced]).to(be(false))
      expect(ceiling[:severity]).to(eq(:note))
    end

    it("does not flag a pure floor requires_python (a floor is not a ceiling)") do
      allow(StillActive::PypiClient).to(receive(:requires_python).and_return(">=3.8"))

      result = described_class.assess(ecosystem: :pypi, name: "numpy", version: "1.21.0", runtime_ranges: {python: python_range})

      expect(result).not_to(have_key(:language_ceiling))
    end

    it("does not flag when the package declares no requires_python") do
      allow(StillActive::PypiClient).to(receive(:requires_python).and_return(nil))

      result = described_class.assess(ecosystem: :pypi, name: "loose", version: "1.0.0", runtime_ranges: {python: python_range})

      expect(result).not_to(have_key(:language_ceiling))
    end

    it("does not read requires_python for a non-Python ecosystem, even with a window") do
      allow(StillActive::PypiClient).to(receive(:requires_python))

      result = described_class.assess(ecosystem: :npm, name: "express", version: "5.2.1", runtime_ranges: {python: python_range})

      expect(result).not_to(have_key(:language_ceiling))
      expect(StillActive::PypiClient).not_to(have_received(:requires_python))
    end

    it("does nothing when the Python support window is unavailable (nil range)") do
      allow(StillActive::PypiClient).to(receive(:requires_python))

      result = described_class.assess(ecosystem: :pypi, name: "numba", version: "0.53.1", runtime_ranges: {})

      expect(result).not_to(have_key(:language_ceiling))
      expect(StillActive::PypiClient).not_to(have_received(:requires_python))
    end
  end

  describe(".assess language ceiling (.NET / NuGet)") do
    let(:dotnet) do
      {
        cycles: [
          {version: Gem::Version.new("10"), eol: false, eol_date: nil},
          {version: Gem::Version.new("8"), eol: false, eol_date: Time.parse("2026-11-10")},
          {version: Gem::Version.new("6"), eol: true, eol_date: Time.parse("2024-11-12")},
          {version: Gem::Version.new("5"), eol: true, eol_date: Time.parse("2022-05-10")},
          {version: Gem::Version.new("3.1"), eol: true, eol_date: Time.parse("2022-12-13")}
        ]
      }
    end
    let(:dotnetfx) do
      {cycles: [{version: Gem::Version.new("4.8"), eol: false, eol_date: nil}, {version: Gem::Version.new("4.5"), eol: true, eol_date: Time.parse("2016-01-12")}]}
    end

    before do
      stub_version(source_repo: "https://github.com/some/pkg")
      stub_package(default_published_at: "2026-06-01T00:00:00Z") # deps.dev default (latest) version 9.9.9
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)
    end

    it("flags a NuGet package targeting only EOL .NET runtimes as a critical ceiling, noting the upgrade lifts it") do
      allow(StillActive::DepsDevClient).to(receive(:target_frameworks).with(name: "deadpkg", version: "1.0.0").and_return(["net5.0", "netcoreapp3.1"]))
      allow(StillActive::DepsDevClient).to(receive(:target_frameworks).with(name: "deadpkg", version: "9.9.9").and_return(["net8.0"]))

      result = described_class.assess(ecosystem: :nuget, name: "deadpkg", version: "1.0.0", runtime_ranges: {dotnet: dotnet, dotnetfx: dotnetfx})

      ceiling = result[:language_ceiling]
      expect(ceiling[:runtime]).to(eq(".NET"))
      expect(ceiling[:eol_forced]).to(be(true))
      expect(ceiling[:severity]).to(eq(:critical))
      expect(ceiling[:ceiling_version]).to(eq("3.1"))
      expect(ceiling[:fixed_by_upgrade]).to(be(true))
    end

    it("does NOT flag a package that also targets netstandard (the escape hatch), even with EOL runtimes") do
      # The Newtonsoft.Json 13.0.3 case: net6.0 + net45 (EOL) + netstandard2.0.
      allow(StillActive::DepsDevClient).to(receive(:target_frameworks).and_return(["net5.0", "net45", "netstandard2.0"]))

      result = described_class.assess(ecosystem: :nuget, name: "newtonsoft.json", version: "13.0.3", runtime_ranges: {dotnet: dotnet, dotnetfx: dotnetfx})

      expect(result).not_to(have_key(:language_ceiling))
    end

    it("does nothing when the .NET support windows are unavailable, without even fetching the frameworks") do
      allow(StillActive::DepsDevClient).to(receive(:target_frameworks))

      result = described_class.assess(ecosystem: :nuget, name: "x", version: "1.0.0", runtime_ranges: {})

      expect(result).not_to(have_key(:language_ceiling))
      expect(StillActive::DepsDevClient).not_to(have_received(:target_frameworks))
    end
  end

  # The Go toolchain is a runtime, not a module: deps.dev keys it `go1.25.5` where
  # the purl says `1.25.5`, its index stops at go1.25.5, and its advisory list is the
  # same 167 for every version (all verified 2026-09-24). So stdlib reads its release
  # lines from endoflife.date and its advisories from OSV by version, never deps.dev.
  describe(".assess Go toolchain (stdlib)") do
    def stub_go_feed(status: 200)
      cycles = [
        {"cycle" => "1.27", "releaseDate" => "2026-08-19", "eol" => false, "latest" => "1.27.1", "latestReleaseDate" => "2026-09-01"},
        {"cycle" => "1.26", "releaseDate" => "2026-02-10", "eol" => false, "latest" => "1.26.8", "latestReleaseDate" => "2026-09-01"},
        {"cycle" => "1.25", "releaseDate" => "2025-08-12", "eol" => "2026-08-19", "latest" => "1.25.14", "latestReleaseDate" => "2026-08-19"}
      ]
      stub_request(:get, "https://endoflife.date/api/go.json")
        .to_return(status: status, headers: {"Content-Type" => "application/json"}, body: cycles.to_json)
    end

    def stub_osv(version:, body: {}, status: 200)
      stub_request(:post, "https://api.osv.dev/v1/query")
        .with(body: {version: version, package: {name: "stdlib", ecosystem: "Go"}}.to_json)
        .to_return(status: status, headers: {"Content-Type" => "application/json"}, body: body.to_json)
    end

    def tls_advisory
      {"id" => "GO-2026-4337", "aliases" => ["CVE-2025-68121"], "summary" => "crypto/tls",
       "affected" => [{"package" => {"name" => "stdlib", "ecosystem" => "Go"},
                       "ranges" => [{"type" => "SEMVER", "events" => [{"introduced" => "1.25.0-0"}, {"fixed" => "1.25.7"}]}]}]}
    end

    def assess(version)
      described_class.assess(ecosystem: :go, name: "stdlib", version: version)
    end

    it("reads the current release as current, with no deps.dev lookup") do
      stub_go_feed
      stub_osv(version: "1.27.1")

      result = assess("1.27.1")

      expect(result).to(include(
        version_used: "1.27.1",
        latest_version: "1.27.1",
        latest_version_release_date: "2026-09-01",
        version_used_release_date: "2026-09-01",
        up_to_date: true,
        deprecated: false,
        vulnerability_count: 0,
        vulnerabilities_checked: true
      ))
      expect(result).not_to(have_key(:version_unresolved))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:ok))
      expect(a_request(:any, /api\.deps\.dev/)).not_to(have_been_made)
    end

    it("accepts the go- and v-prefixed forms generators write") do
      stub_go_feed
      stub_osv(version: "1.27.1")

      expect(assess("go1.27.1")).to(include(latest_version: "1.27.1", up_to_date: true))
      expect(assess("v1.27.1")).to(include(latest_version: "1.27.1", up_to_date: true))
    end

    # Go 1.20 and earlier shipped their first release as go1.20, and OSV answers it.
    it("queries OSV for a two-part release") do
      stub_go_feed
      stub_osv(version: "1.25", body: {vulns: [tls_advisory]})

      result = assess("1.25")

      expect(result).to(include(vulnerability_count: 1, version_used_release_date: "2025-08-12"))
      expect(result).not_to(have_key(:version_unresolved))
    end

    # OSV writes a Go prerelease 1.27.0-rc.1, so asking for 1.27rc1 would come back
    # empty and read as clean.
    it("reads a prerelease as :unknown without asking OSV") do
      stub_go_feed

      result = nil
      expect { result = assess("go1.27rc1") }.to(output(/not checked/).to_stderr)

      expect(result).to(include(vulnerabilities_checked: false))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
      expect(a_request(:post, /api\.osv\.dev/)).not_to(have_been_made)
    end

    it("reports an end-of-life line's advisories and says the line is over") do
      stub_go_feed
      stub_osv(version: "1.25.5", body: {vulns: [tls_advisory]})

      result = assess("1.25.5")

      expect(result).to(include(up_to_date: false, deprecated: true, vulnerability_count: 1))
      expect(result[:deprecation_reason]).to(eq("The Go team ended the 1.25 release line on 2026-08-19; it gets no further security fixes. Upgrade to 1.27.1."))
      expect(result[:vulnerabilities].first).to(include(id: "GO-2026-4337", fixed_versions: ["1.25.7"]))
      # A patch that isn't its line's latest has no release date in the feed.
      expect(result[:version_used_release_date]).to(be_nil)
    end

    it("reads a supported older line as behind but not deprecated") do
      stub_go_feed
      stub_osv(version: "1.26.8")

      expect(assess("1.26.8")).to(include(up_to_date: false, deprecated: false, deprecation_reason: nil))
    end

    # A failed OSV answer is not an all-clear: the version reads :unknown.
    it("reads :unknown when OSV can't answer") do
      stub_go_feed
      stub_osv(version: "1.27.1", body: {vulns: [], next_page_token: "abc"})

      result = nil
      # Only JSON carries the status, so the miss has to be said out loud too.
      expect { result = assess("1.27.1") }.to(output(/go\/stdlib@1\.27\.1.*not checked/).to_stderr)

      expect(result).to(include(vulnerabilities_checked: false))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
    end

    it("reads :unknown for a release line the feed doesn't list") do
      stub_go_feed
      stub_osv(version: "1.99.0")

      expect(assess("1.99.0")[:version_unresolved]).to(be(true))
    end

    it("reads :unknown with no latest when the feed is down") do
      stub_go_feed(status: 503)
      stub_osv(version: "1.27.1")

      result = assess("1.27.1")

      expect(result).to(include(latest_version: nil, deprecated: false))
      expect(StillActive::StatusHelper.gem_status(result)).to(eq(:unknown))
    end

    it("leaves a Go module named stdlib elsewhere to the registry path") do
      stub_version(source_repo: "https://github.com/x/stdlib")
      stub_package(default_published_at: "2026-06-01T00:00:00Z")
      stub_project_scorecard
      stub_ecosystems_repo(archived: false)
      stub_request(:post, "https://api.osv.dev/v1/query").to_return(status: 200, body: "{}", headers: {"Content-Type" => "application/json"})

      described_class.assess(ecosystem: :go, name: "github.com/x/stdlib", version: "v1.0.0")

      expect(a_request(:get, /endoflife\.date/)).not_to(have_been_made)
    end
  end
end
