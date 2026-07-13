# frozen_string_literal: true

RSpec.describe(StillActive::DepsDevClient) do
  describe(".advisory_schema_ok?") do
    # Guards against the alpha v3alpha API renaming/dropping `advisoryKeys`, which
    # would degrade every vuln count to 0 and render known-vulnerable packages
    # "clean" (a silent false-negative on a tool that trades on no-false-positives).
    def stub_canary(body)
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/pypi/packages/django/versions/3\.0\.0})
        .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: body.to_json)
    end

    it "is true when the canary package still carries advisoryKeys (schema intact)" do
      stub_canary({ "advisoryKeys" => [{ "id" => "GHSA-x" }, { "id" => "GHSA-y" }] })
      expect(described_class.advisory_schema_ok?).to(be(true))
    end

    it "is false when the canary comes back with no advisories (field renamed/dropped)" do
      stub_canary({ "advisoryKeys" => [] })
      expect(described_class.advisory_schema_ok?).to(be(false))
    end

    it "is false when the canary can't be reached (can't confirm the schema)" do
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/pypi/packages/django/versions/3\.0\.0}).to_return(status: 500)
      expect(described_class.advisory_schema_ok?).to(be(false))
    end
  end

  describe(".version_info") do
    it("returns advisory keys and project id for a known gem") do
      VCR.use_cassette("deps_dev_version") do
        result = described_class.version_info(gem_name: "nokogiri", version: "1.19.1")

        expect(result).to(include(
          advisory_keys: an_instance_of(Array),
          project_id: "github.com/sparklemotion/nokogiri",
        ))
      end
    end

    it("extracts the locked version's publishedAt (the cross-ecosystem libyear input)") do
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/pypi/packages/lxml/versions/6\.0\.2})
        .to_return(
          status: 200,
          headers: { "Content-Type" => "application/json" },
          body: { "advisoryKeys" => [], "publishedAt" => "2025-09-22T04:04:12Z" }.to_json,
        )
      result = described_class.version_info(gem_name: "lxml", version: "6.0.2", system: :pypi)
      expect(result[:published_at]).to(eq("2025-09-22T04:04:12Z"))
    end

    it("ignores a GitHub funding link (github.com/sponsors/X) as a repository") do
      # deps.dev sometimes returns a SOURCE_REPO of https://github.com/sponsors/<user>
      # (a funding link, not a repo). Parsed as owner/repo it becomes sponsors/<user>,
      # which 404s and renders a blank repo cell. Reserved GitHub paths carry no repo.
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/pypi/packages/rpds-py/versions/1\.0\.0})
        .to_return(
          status: 200,
          headers: { "Content-Type" => "application/json" },
          body: { "advisoryKeys" => [], "links" => [{ "label" => "SOURCE_REPO", "url" => "https://github.com/sponsors/Julian" }] }.to_json,
        )
      result = described_class.version_info(gem_name: "rpds-py", version: "1.0.0", system: :pypi)
      expect(result[:project_id]).to(be_nil)
    end

    it("returns nil when gem_name is nil") do
      expect(described_class.version_info(gem_name: nil, version: "1.0.0")).to(be_nil)
    end

    describe(".target_frameworks") do
      it("returns the NuGet target framework monikers for a version") do
        stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/nuget/packages/newtonsoft\.json/versions/13\.0\.3:requirements})
          .to_return(
            status: 200,
            headers: { "Content-Type" => "application/json" },
            body: { "nuget" => { "targetFrameworks" => ["net45", "net6.0", "netstandard2.0"] } }.to_json,
          )
        expect(described_class.target_frameworks(name: "newtonsoft.json", version: "13.0.3"))
          .to(eq(["net45", "net6.0", "netstandard2.0"]))
      end

      it("returns [] for nil input or an unknown package (404), never raising") do
        expect(described_class.target_frameworks(name: nil, version: "1")).to(eq([]))
        stub_request(:get, /api\.deps\.dev/).to_return(status: 404)
        expect(described_class.target_frameworks(name: "ghost", version: "1")).to(eq([]))
      end
    end

    it("returns nil when version is nil") do
      expect(described_class.version_info(gem_name: "nokogiri", version: nil)).to(be_nil)
    end

    it("queries the rubygems system by default") do
      stub = stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/rubygems/packages/nokogiri/versions/1\.19\.1})
        .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")

      described_class.version_info(gem_name: "nokogiri", version: "1.19.1")
      expect(stub).to(have_been_requested)
    end

    it("queries the given ecosystem's deps.dev system path") do
      stub = stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/npm/packages/express/versions/5\.2\.1})
        .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")

      described_class.version_info(gem_name: "express", version: "5.2.1", system: :npm)
      expect(stub).to(have_been_requested)
    end

    it("percent-encodes a scoped npm name so the path segment stays intact") do
      # The scope slash must stay percent-encoded (%2F) so `core` isn't read as a
      # separate path segment. WebMock/Addressable decodes %40 back to @.
      stub = stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/npm/packages/@babel%2Fcore/versions/7\.0\.0})
        .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")

      described_class.version_info(gem_name: "@babel/core", version: "7.0.0", system: :npm)
      expect(stub).to(have_been_requested)
    end
  end

  describe(".latest_release_date") do
    def package_body(versions)
      { "versions" => versions }.to_json
    end

    it("returns the default version's publishedAt (the package's freshness signal)") do
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/pypi/packages/requests\z}).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: package_body([
          { "versionKey" => { "version" => "2.31.0" }, "isDefault" => false, "publishedAt" => "2023-05-22T15:12:42Z" },
          { "versionKey" => { "version" => "2.32.5" }, "isDefault" => true, "publishedAt" => "2025-08-18T20:46:00Z" },
        ]),
      )

      expect(described_class.latest_release_date(name: "requests", system: :pypi)).to(eq("2025-08-18T20:46:00Z"))
    end

    it("queries the rubygems system by default") do
      stub = stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/rubygems/packages/nokogiri\z})
        .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: package_body([]))

      described_class.latest_release_date(name: "nokogiri")
      expect(stub).to(have_been_requested)
    end

    it("prefers the latest stable version even when deps.dev flags an older one as default") do
      # deps.dev's isDefault is not reliably the newest release: cargo/wasi flags
      # 0.7.0 (2019) as default while 0.14.7 (2025) ships. Trusting isDefault reads
      # an active crate as years-stale (a false SA002) and paints a downgrade as an
      # upgrade. The latest STABLE version by version number is the honest latest.
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: package_body([
          { "versionKey" => { "version" => "0.7.0" }, "isDefault" => true, "publishedAt" => "2019-08-29T15:32:47Z" },
          { "versionKey" => { "version" => "0.14.7+wasi-0.2.4" }, "isDefault" => false, "publishedAt" => "2025-09-01T00:00:00Z" },
        ]),
      )

      expect(described_class.default_version_info(name: "wasi", system: :cargo))
        .to(eq({ version: "0.14.7+wasi-0.2.4", published_at: "2025-09-01T00:00:00Z" }))
    end

    it("skips a deprecated (yanked) release even when it is the newest by version") do
      # Dropping the reliance on isDefault lost its implicit yanked-version guard,
      # so filter deps.dev's isDeprecated flag explicitly: recommending an upgrade
      # to a pulled release (and using it as the poison-pill "latest" baseline)
      # would be exactly the kind of confident-wrong answer this tool must avoid.
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: package_body([
          { "versionKey" => { "version" => "1.0.0" }, "isDefault" => false, "isDeprecated" => false, "publishedAt" => "2024-01-01T00:00:00Z" },
          { "versionKey" => { "version" => "2.0.0" }, "isDefault" => false, "isDeprecated" => true, "publishedAt" => "2025-01-01T00:00:00Z" },
        ]),
      )

      expect(described_class.default_version_info(name: "pkg", system: :cargo)&.dig(:version)).to(eq("1.0.0"))
    end

    it("ignores a prerelease flagged as default, using the latest stable release") do
      # pypi/httpx: deps.dev flags 1.0.0.dev3 as default while the latest stable is
      # 0.28.1; a current 0.28.1 pin must not read as "behind 1.0.0.dev3".
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: package_body([
          { "versionKey" => { "version" => "0.28.1" }, "isDefault" => false, "publishedAt" => "2024-12-06T00:00:00Z" },
          { "versionKey" => { "version" => "1.0.0.dev3" }, "isDefault" => true, "publishedAt" => "2025-01-01T00:00:00Z" },
        ]),
      )

      expect(described_class.default_version_info(name: "httpx", system: :pypi)&.dig(:version)).to(eq("0.28.1"))
    end

    it("falls back to the newest publishedAt when every version is a prerelease") do
      # No stable release parses, so the release-driven freshness signal falls back
      # to the newest date rather than reading a prerelease-only package as dormant.
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: package_body([
          { "versionKey" => { "version" => "0.1.0-rc1" }, "isDefault" => false, "publishedAt" => "2024-01-01T00:00:00Z" },
          { "versionKey" => { "version" => "0.2.0-rc1" }, "isDefault" => false, "publishedAt" => "2024-06-01T00:00:00Z" },
        ]),
      )

      expect(described_class.latest_release_date(name: "all-pre", system: :cargo)).to(eq("2024-06-01T00:00:00Z"))
    end

    it("returns nil when name is nil") do
      expect(described_class.latest_release_date(name: nil)).to(be_nil)
    end

    it("returns nil when the package is unknown (404 -> no body)") do
      stub_request(:get, /api\.deps\.dev/).to_return(status: 404)

      expect(described_class.latest_release_date(name: "does-not-exist", system: :npm)).to(be_nil)
    end

    it("returns nil when the package has no versions") do
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200, headers: { "Content-Type" => "application/json" }, body: package_body([]),
      )

      expect(described_class.latest_release_date(name: "empty", system: :npm)).to(be_nil)
    end

    it("returns nil on timeout") do
      stub_request(:get, /api\.deps\.dev/).to_timeout

      expect(described_class.version_info(gem_name: "nokogiri", version: "1.19.1")).to(be_nil)
    end

    it("returns nil on connection refused") do
      stub_request(:get, /api\.deps\.dev/).to_raise(Errno::ECONNREFUSED)

      expect(described_class.version_info(gem_name: "nokogiri", version: "1.19.1")).to(be_nil)
    end
  end

  describe(".advisory_detail") do
    it("returns advisory details for a known advisory") do
      body = {
        "advisoryKey" => { "id" => "GHSA-test-1234" },
        "url" => "https://github.com/advisories/GHSA-test-1234",
        "title" => "Test vulnerability",
        "aliases" => ["CVE-2024-1234"],
        "cvss3Score" => 9.8,
        "cvss3Vector" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      }
      stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/}).to_return(
        status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" },
      )

      result = described_class.advisory_detail(advisory_id: "GHSA-test-1234")
      expect(result).to(include(
        id: "GHSA-test-1234",
        title: "Test vulnerability",
        cvss3_score: 9.8,
        aliases: ["CVE-2024-1234"],
        source: "deps.dev",
      ))
    end

    it("surfaces deps.dev's real string-array aliases (the live v3alpha API returns [\"CVE-...\"], not objects)") do
      # Verified against api.deps.dev: aliases is an array of bare id strings. The
      # previous object-shape stubs never matched reality, so every CVE alias was
      # silently dropped and findings arrived with an empty aliases list.
      body = {
        "advisoryKey" => { "id" => "GHSA-real-shape" },
        "aliases" => ["CVE-2026-54906", "GHSA-xj5v-6v4g-jfw6"],
      }
      stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/}).to_return(
        status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" },
      )

      expect(described_class.advisory_detail(advisory_id: "GHSA-real-shape")[:aliases])
        .to(eq(["CVE-2026-54906", "GHSA-xj5v-6v4g-jfw6"]))
    end

    it("still tolerates the legacy object shape defensively (alpha API could regress)") do
      body = {
        "advisoryKey" => { "id" => "GHSA-nullalias" },
        "aliases" => [{ "id" => "CVE-2024-9" }, { "foo" => "bar" }, {}, "CVE-2024-10"],
      }
      stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/}).to_return(
        status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" },
      )

      expect(described_class.advisory_detail(advisory_id: "GHSA-nullalias")[:aliases]).to(eq(["CVE-2024-9", "CVE-2024-10"]))
    end

    it("extracts cvss2_score when present") do
      body = {
        "advisoryKey" => { "id" => "GHSA-old-vuln" },
        "url" => "https://github.com/advisories/GHSA-old-vuln",
        "title" => "Old vulnerability",
        "aliases" => [],
        "cvss3Score" => nil,
        "cvss3Vector" => nil,
        "cvss2Score" => 7.5,
      }
      stub_request(:get, %r{api\.deps\.dev/v3alpha/advisories/}).to_return(
        status: 200, body: body.to_json, headers: { "Content-Type" => "application/json" },
      )

      result = described_class.advisory_detail(advisory_id: "GHSA-old-vuln")
      expect(result).to(include(cvss3_score: nil, cvss2_score: 7.5))
    end

    it("returns nil when advisory_id is nil") do
      expect(described_class.advisory_detail(advisory_id: nil)).to(be_nil)
    end

    it("returns nil on timeout") do
      stub_request(:get, /api\.deps\.dev/).to_timeout
      expect(described_class.advisory_detail(advisory_id: "GHSA-test")).to(be_nil)
    end
  end

  describe(".project_scorecard") do
    it("returns score and date for a known project") do
      VCR.use_cassette("deps_dev_project") do
        result = described_class.project_scorecard(project_id: "github.com/sparklemotion/nokogiri")

        expect(result).to(include(
          score: a_value > 0,
          date: a_string_matching(/\d{4}-\d{2}-\d{2}/),
        ))
      end
    end

    it("returns nil when project_id is nil") do
      expect(described_class.project_scorecard(project_id: nil)).to(be_nil)
    end

    it("returns nil on timeout") do
      stub_request(:get, /api\.deps\.dev/).to_timeout

      expect(described_class.project_scorecard(project_id: "github.com/sparklemotion/nokogiri")).to(be_nil)
    end

    it("extracts the OpenSSF 'Maintained' sub-check score") do
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: {
          scorecard: {
            overallScore: 7.5,
            date: "2026-01-02",
            checks: [
              { name: "Code-Review", score: 8 },
              { name: "Maintained", score: 10 },
            ],
          },
        }.to_json,
      )

      result = described_class.project_scorecard(project_id: "github.com/some/repo")

      expect(result).to(include(score: 7.5, maintained: 10))
    end

    it("reports a nil 'Maintained' score when the check is absent") do
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        body: { scorecard: { overallScore: 6.0, date: "2026-01-02", checks: [] } }.to_json,
      )

      expect(described_class.project_scorecard(project_id: "github.com/some/repo")).to(include(maintained: nil))
    end

    it("degrades to a nil 'Maintained' score on a malformed checks payload (does not crash the gem)") do
      stub_request(:get, /api\.deps\.dev/).to_return(
        status: 200,
        headers: { "Content-Type" => "application/json" },
        # A non-array `checks` is a contract violation; it must not raise and
        # vanish the gem from the whole audit via the per-gem rescue.
        body: { scorecard: { overallScore: 6.0, date: "2026-01-02", checks: { "Maintained" => 10 } } }.to_json,
      )

      expect(described_class.project_scorecard(project_id: "github.com/some/repo")).to(include(maintained: nil))
    end
  end

  describe("#extract_project_id (SOURCE_REPO URL parsing)") do
    def project_id(url)
      described_class.send(:extract_project_id, { "links" => [{ "label" => "SOURCE_REPO", "url" => url }] })
    end

    it("keeps the full path for a GitLab subgroup project") do
      expect(project_id("https://gitlab.com/group/subgroup/project")).to(eq("gitlab.com/group/subgroup/project"))
    end

    it("keeps deeply nested GitLab subgroups") do
      expect(project_id("https://gitlab.com/a/b/c/project")).to(eq("gitlab.com/a/b/c/project"))
    end

    it("strips GitLab's /-/ tree suffix but keeps the subgroup path") do
      expect(project_id("https://gitlab.com/group/sub/project/-/tree/main")).to(eq("gitlab.com/group/sub/project"))
    end

    it("keeps a plain two-level GitLab project") do
      expect(project_id("https://gitlab.com/owner/project")).to(eq("gitlab.com/owner/project"))
    end

    it("keeps owner/repo for GitHub") do
      expect(project_id("https://github.com/rails/rails")).to(eq("github.com/rails/rails"))
    end

    it("strips GitHub tree/blob extras") do
      expect(project_id("https://github.com/rails/rails/tree/v7.1.0")).to(eq("github.com/rails/rails"))
    end

    it("strips a trailing slash and .git suffix") do
      expect(project_id("https://github.com/rails/rails/")).to(eq("github.com/rails/rails"))
      expect(project_id("https://github.com/rails/rails.git")).to(eq("github.com/rails/rails"))
    end

    it("normalizes a git:// scheme URL (deps.dev returns these for many npm packages)") do
      # Left unstripped, `git://github.com/gruntjs/grunt.git` mis-parses to
      # `git:/github.com/gruntjs`, which then 400s the deps.dev projects lookup (noise)
      # and drops the repo signals. Normalizing recovers the clean id and the data.
      expect(project_id("git://github.com/gruntjs/grunt.git")).to(eq("github.com/gruntjs/grunt"))
    end

    it("normalizes git+https and git+ssh scheme URLs") do
      expect(project_id("git+https://github.com/owner/repo.git")).to(eq("github.com/owner/repo"))
      expect(project_id("git+ssh://git@github.com/owner/repo.git")).to(eq("github.com/owner/repo"))
    end

    it("strips ssh userinfo before the host") do
      expect(project_id("ssh://git@github.com/owner/repo.git")).to(eq("github.com/owner/repo"))
    end

    it("handles the scp-style git remote (host:owner/repo), but not a port") do
      expect(project_id("git@github.com:owner/repo.git")).to(eq("github.com/owner/repo"))
      expect(project_id("git+ssh://git@github.com:owner/repo.git")).to(eq("github.com/owner/repo"))
      # a real port after the host is not a path separator
      expect(project_id("https://gitlab.example.com:8443/group/project")).to(eq("gitlab.example.com:8443/group/project"))
    end

    it("returns nil when there is no SOURCE_REPO link") do
      expect(described_class.send(:extract_project_id, { "links" => [] })).to(be_nil)
    end
  end
end
