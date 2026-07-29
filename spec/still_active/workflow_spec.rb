# frozen_string_literal: true

RSpec.describe(StillActive::Workflow) do
  before do
    # Fresh config per example so the global singleton (e.g. the --alternatives
    # flag) can't leak across the randomized suite.
    StillActive.reset
    # Keep the optional ruby-advisory-db second source out of the default path so
    # tests don't depend on a local `bundle audit update` checkout. The merge is
    # exercised explicitly in its own context below.
    allow(StillActive::RubyAdvisoryDb).to(receive(:load).and_return(nil))
    # Poison-pill enrichment fires for any dormant gem; default it to "no declared
    # deps" so existing dormant-gem contexts stay network-free. The poison-pill
    # context overrides this per example. (WebMock would otherwise raise on the
    # unstubbed packages.ecosyste.ms call.)
    allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([]))
    # Language-runtime ceiling enrichment fetches the Ruby support window once per
    # run. Default it off (nil) so existing contexts stay network-free; the ceiling
    # context stubs a real range. (WebMock would otherwise raise on endoflife.date.)
    allow(StillActive::RubyHelper).to(receive(:supported_ruby_range).and_return(nil))
    # Pin a GitHub token so provider_for selects GithubClient (the path these
    # integration specs and their VCR cassettes assume), independent of whether
    # the host running the suite happens to have a `gh` token. The no-token
    # ecosyste.ms fallback is covered explicitly in its own client + dispatch
    # specs, which override this.
    StillActive.config.github_oauth_token = "ghp_test_token"
  end

  describe("#call") do
    subject(:result) { described_class.call }

    context("when configured to use gems") do
      let(:gems) { ["rails", "nokogiri"] }

      before { StillActive.config.gems = gems.map { |name| {name: name} } }

      it("returns a hash containing information about gems") do
        VCR.use_cassette("gems") do
          expect(result).to(include(**{
            "rails" => hash_including(
              latest_version: "8.1.2",
              # 8.1.0.rc1 predates the shipped 8.1.2, so it is dropped as noise.
              latest_pre_release_version: nil,
              repository_url: "https://github.com/rails/rails",
              ruby_gems_url: "https://rubygems.org/gems/rails",
              scorecard_score: a_value > 0,
              vulnerability_count: an_instance_of(Integer)
            ),
            "nokogiri" => hash_including(
              latest_version: "1.19.1",
              # 1.18.0.rc1 predates the shipped 1.19.1, so it is dropped as noise.
              latest_pre_release_version: nil,
              repository_url: "https://github.com/sparklemotion/nokogiri",
              ruby_gems_url: "https://rubygems.org/gems/nokogiri",
              scorecard_score: a_value > 0,
              vulnerability_count: an_instance_of(Integer)
            )
          }))
        end
      end
    end

    context("when ruby-advisory-db is available as a second source") do
      before do
        StillActive.config.gems = [{name: "rack", version: "2.0.0"}]
        allow(Gems).to(receive(:versions).with("rack").and_return([
          {"number" => "2.0.0", "prerelease" => false, "created_at" => "2016-05-06T00:00:00Z", "licenses" => ["MIT"]}
        ]))
        allow(Gems).to(receive(:info).with("rack").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
        allow(StillActive::DepsDevClient).to(receive_messages(
          version_info: {advisory_keys: ["GHSA-deps"], project_id: nil},
          project_scorecard: nil,
          advisory_detail: {id: "GHSA-deps", aliases: [], title: "from deps.dev", cvss3_score: 7.5, source: "deps.dev"}
        ))
        allow(StillActive::RubyAdvisoryDb).to(receive(:load).and_return(:fake_db))

        # rack's gemspec may already be activated by another spec, in which case
        # repository_info resolves a real github.com/rack/rack URL and the commit
        # lookup makes a live HTTP call (no cassette here) that propagates out and
        # discards the gem's entry. Pin the repo-derived fields so this context
        # exercises only the advisory merge, regardless of what's been activated.
        allow(described_class).to(receive(:repo_signals).and_return({}))
      end

      it("appends advisories unique to ruby-advisory-db") do
        allow(StillActive::RubyAdvisoryDb).to(receive(:advisories_for).and_return(
          [{id: "GHSA-radb", aliases: [], cvss3_score: 5.0, source: "ruby-advisory-db"}]
        ))

        data = result["rack"]
        expect(data[:vulnerability_count]).to(eq(2))
        expect(data[:vulnerabilities].map { |v| v[:source] }).to(contain_exactly("deps.dev", "ruby-advisory-db"))
      end

      it("deduplicates an advisory reported by both sources into one merged entry") do
        allow(StillActive::RubyAdvisoryDb).to(receive(:advisories_for).and_return(
          [{id: "GHSA-deps", aliases: ["OSVDB-1"], cvss3_score: 6.0, source: "ruby-advisory-db"}]
        ))

        data = result["rack"]
        expect(data[:vulnerability_count]).to(eq(1))
        expect(data[:vulnerabilities].first).to(include(source: "merged", title: "from deps.dev", cvss3_score: 7.5))
      end

      it("keeps a confirmed advisory as a minimal entry when its deps.dev detail fetch fails, rather than dropping it and reading the gem as clean") do
        # A 429/timeout on the per-advisory detail call returns nil; the key is
        # still evidence the version is vulnerable, so it must survive.
        allow(StillActive::DepsDevClient).to(receive(:advisory_detail).and_return(nil))
        allow(StillActive::RubyAdvisoryDb).to(receive(:advisories_for).and_return([]))

        data = result["rack"]
        expect(data[:vulnerability_count]).to(eq(1))
        expect(data[:vulnerabilities].first).to(include(id: "GHSA-deps", source: "deps.dev"))
        # Unscored, so a severity gate fails closed on it.
        expect(StillActive::VulnerabilityHelper.severity_at_or_above?(data[:vulnerabilities], "high")).to(be(true))
      end
    end

    context("when a gem version is yanked") do
      before do
        StillActive.config.gems = [{name: "yanked_gem", version: "0.9.0"}]

        # Gem exists but version 0.9.0 is not in the list (yanked)
        allow(Gems).to(receive(:versions).with("yanked_gem").and_return([
          {"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z"}
        ]))
        allow(Gems).to(receive(:info).with("yanked_gem").and_return({
          "homepage_uri" => nil,
          "source_code_uri" => nil
        }))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
      end

      it("sets version_yanked to true") do
        expect(result).to(include(
          "yanked_gem" => hash_including(version_yanked: true)
        ))
      end
    end

    context("when a gem version is not yanked") do
      before do
        StillActive.config.gems = [{name: "good_gem", version: "1.0.0"}]

        allow(Gems).to(receive(:versions).with("good_gem").and_return([
          {"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z"}
        ]))
        allow(Gems).to(receive(:info).with("good_gem").and_return({
          "homepage_uri" => nil,
          "source_code_uri" => nil
        }))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
      end

      it("sets version_yanked to false") do
        expect(result).to(include(
          "good_gem" => hash_including(version_yanked: false)
        ))
      end
    end

    context("when a gem is git-sourced") do
      before do
        StillActive.config.gems = [{name: "git_gem", version: "0.5.0", source_type: :git}]
        allow(Gems).to(receive(:versions))
        allow(StillActive::DepsDevClient).to(receive(:project_scorecard).and_return(nil))
      end

      it("does not query Gems.versions") do
        result
        expect(Gems).not_to(have_received(:versions))
      end

      it("sets source_type to :git") do
        expect(result).to(include(
          "git_gem" => hash_including(source_type: :git)
        ))
      end

      it("does not set version_yanked or libyear") do
        data = result["git_gem"]
        expect(data).not_to(have_key(:version_yanked))
        expect(data).not_to(have_key(:libyear))
      end
    end

    context("when a gem is path-sourced") do
      before do
        StillActive.config.gems = [{name: "path_gem", version: "0.1.0", source_type: :path}]
        allow(Gems).to(receive(:versions))
        allow(StillActive::DepsDevClient).to(receive(:project_scorecard).and_return(nil))
      end

      it("does not query Gems.versions") do
        result
        expect(Gems).not_to(have_received(:versions))
      end

      it("sets source_type to :path") do
        expect(result).to(include(
          "path_gem" => hash_including(source_type: :path)
        ))
      end

      it("does not set version_yanked or libyear") do
        data = result["path_gem"]
        expect(data).not_to(have_key(:version_yanked))
        expect(data).not_to(have_key(:libyear))
      end
    end

    context("when a gem is from GitHub Packages") do
      let(:ghp_versions) do
        [
          {"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z"}
        ]
      end

      before do
        StillActive.config.gems = [{
          name: "private_gem",
          version: "1.0.0",
          source_type: :rubygems,
          source_uri: "https://rubygems.pkg.github.com/my-org"
        }]
        StillActive.config.github_oauth_token = "ghp_test_token"
        stub_request(:get, "https://rubygems.pkg.github.com/my-org/api/v1/gems/private_gem/versions.json")
          .to_return(status: 200, body: ghp_versions.to_json, headers: {"Content-Type" => "application/json"})
        allow(Gems).to(receive(:info).with("private_gem").and_return({
          "homepage_uri" => nil,
          "source_code_uri" => nil
        }))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
      end

      it("fetches versions from GitHub Packages API") do
        result
        expect(WebMock).to(have_requested(:get, "https://rubygems.pkg.github.com/my-org/api/v1/gems/private_gem/versions.json")
          .with(headers: {"Authorization" => "Bearer ghp_test_token"}))
      end

      it("returns version data from GitHub Packages") do
        expect(result).to(include(
          "private_gem" => hash_including(latest_version: "1.0.0")
        ))
      end

      # A `/` in the (lockfile-controlled) gem name does NOT raise; unescaped it
      # silently redirects the lookup to an attacker-chosen path on the trusted
      # host. Assert the literal path string, because WebMock normalizes `%2F`
      # back to `/` and so can't tell the escaped request from the injected one.
      it("escapes path separators so a crafted gem name can't redirect the request to another path") do
        StillActive.config.gems = [{
          name: "evil/../secrets",
          version: "1.0.0",
          source_type: :rubygems,
          source_uri: "https://rubygems.pkg.github.com/my-org"
        }]
        allow(Gems).to(receive(:info).with("evil/../secrets").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
        requested_path = nil
        allow(StillActive::HttpHelper).to(receive(:get_json)) do |_base, path, **_kwargs|
          requested_path = path
          ghp_versions
        end

        result

        expect(requested_path).to(eq("/my-org/api/v1/gems/evil%2F..%2Fsecrets/versions.json"))
      end

      # A space raises URI::InvalidComponentError on `uri.path =`; the swallowing
      # rescue in #call hides the crash, so the gem silently yields no versions.
      it("escapes a gem name that would otherwise raise on an invalid URI path, instead of silently yielding nothing") do
        StillActive.config.gems = [{
          name: "bad name",
          version: "1.0.0",
          source_type: :rubygems,
          source_uri: "https://rubygems.pkg.github.com/my-org"
        }]
        allow(Gems).to(receive(:info).with("bad name").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
        stub_request(:get, "https://rubygems.pkg.github.com/my-org/api/v1/gems/bad+name/versions.json")
          .to_return(status: 200, body: ghp_versions.to_json, headers: {"Content-Type" => "application/json"})

        expect(result).to(include("bad name" => hash_including(latest_version: "1.0.0")))
      end
    end

    context("when a gem is from Artifactory") do
      let(:source_uri) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/" }
      let(:versions_api_url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/api/v1/versions/private_gem.json" }
      let(:info_url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/info/private_gem" }
      let(:aql_url) { "https://my-org.jfrog.io/artifactory/api/search/aql" }
      let(:artifactory_versions) do
        [
          {"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z", "licenses" => ["MIT"]}
        ]
      end

      before do
        StillActive.config.gems = [{
          name: "private_gem",
          version: "1.0.0",
          source_type: :rubygems,
          source_uri: source_uri
        }]
        allow(Gems).to(receive(:info).with("private_gem").and_return({
          "homepage_uri" => nil,
          "source_code_uri" => nil
        }))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
        # These cases exercise the versions API and AQL, which are reached only
        # when the host serves no compact index.
        stub_request(:get, info_url).to_return(status: 404)
      end

      # Issue #142: the installed version was reported YANKED because the merged
      # versions API only knew the rubygems.org placeholder, so the real version
      # was missing from the list. The compact index knows it.
      it("does not report a version yanked when only the merged versions API is missing it") do
        StillActive.config.artifactory_token = "art-test-token"
        StillActive.config.artifactory_host = "my-org.jfrog.io"
        stub_request(:get, info_url)
          .to_return(status: 200, body: "---\n0.0.3 |checksum:40c1\n1.0.0 |checksum:39f6\n")
        stub_request(:get, versions_api_url).to_return(
          status: 200,
          body: [{"number" => "0.0.3", "created_at" => "2017-05-18T17:45:27.846Z"}].to_json,
          headers: {"Content-Type" => "application/json"}
        )

        expect(result).to(include(
          "private_gem" => hash_including(version_yanked: false, latest_version: "1.0.0")
        ))
      end

      it("does not link a private-source gem to the public rubygems.org page (#43 family)") do
        # rubygems.org/gems/<name> for a private gem is a public name collision (for
        # sidekiq-pro, the 0.0.3 squat-warning decoy), not the gem the user resolves.
        # created_at inline so the compact index self-dates (no versions-API call).
        stub_request(:get, info_url)
          .to_return(status: 200, body: "---\n1.0.0 |checksum:aa,created_at:2025-06-01T00:00:00Z\n")

        expect(result["private_gem"]).to(include(latest_version: "1.0.0"))
        expect(result["private_gem"]).not_to(include(:ruby_gems_url))
      end

      it("fetches versions from the Artifactory versions API with Bearer auth") do
        StillActive.config.artifactory_token = "art-test-token"
        StillActive.config.artifactory_host = "my-org.jfrog.io"
        stub_request(:get, versions_api_url)
          .to_return(status: 200, body: artifactory_versions.to_json, headers: {"Content-Type" => "application/json"})

        result

        expect(WebMock).to(have_requested(:get, versions_api_url)
          .with(headers: {"Authorization" => "Bearer art-test-token"}))
        expect(result).to(include(
          "private_gem" => hash_including(latest_version: "1.0.0")
        ))
      end

      it("sends Basic auth when Bundler.settings has user:password credentials") do
        allow(Bundler.settings).to(receive(:[]).with(source_uri).and_return("alice:secret"))
        allow(Bundler.settings).to(receive(:[]).with("my-org.jfrog.io").and_return(nil))
        stub_request(:get, versions_api_url)
          .with(headers: {"Authorization" => /^Basic /})
          .to_return(status: 200, body: artifactory_versions.to_json, headers: {"Content-Type" => "application/json"})

        result

        expect(WebMock).to(have_requested(:get, versions_api_url))
        expect(result).to(include(
          "private_gem" => hash_including(latest_version: "1.0.0")
        ))
      end

      it("falls back to AQL when the versions API returns 404") do
        StillActive.config.artifactory_token = "art-test-token"
        StillActive.config.artifactory_host = "my-org.jfrog.io"
        stub_request(:get, versions_api_url).to_return(status: 404)
        aql_body = {
          "results" => [
            {"name" => "private_gem-2.0.0.gem", "created" => "2025-07-01T00:00:00Z"},
            {"name" => "private_gem-2.0.0-x86_64-linux.gem", "created" => "2025-07-02T00:00:00Z"},
            {"name" => "private_gem-1.0.0.gem", "created" => "2025-06-01T00:00:00Z"}
          ]
        }
        stub_request(:post, aql_url)
          .with(body: /private_gem-\*\.gem/)
          .to_return(status: 200, body: aql_body.to_json, headers: {"Content-Type" => "application/json"})

        expect(result).to(include(
          "private_gem" => hash_including(latest_version: "2.0.0")
        ))
      end
    end

    context("when a progress block is given") do
      before do
        StillActive.config.gems = [
          {name: "gem_a", version: "1.0.0"},
          {name: "gem_b", version: "2.0.0"},
          {name: "gem_c", version: "3.0.0"}
        ]
        allow(Gems).to(receive_messages(
          versions: [{"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z"}],
          info: {"homepage_uri" => nil, "source_code_uri" => nil}
        ))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
      end

      it("yields completed count and total for each gem") do
        progress = []
        described_class.call { |done, total| progress << [done, total] }
        expect(progress.map(&:last)).to(all(eq(3)))
        expect(progress.map(&:first).sort).to(eq([1, 2, 3]))
      end
    end

    context("when gems resolve in a non-alphabetical order") do
      # Gems land in the result hash as their async tasks finish, so insertion
      # order is completion order (nondeterministic across runs). Every consumer
      # (JSON, SARIF, the baseline diff) needs a stable order to be diffable.
      before do
        StillActive.config.gems = [
          {name: "zebra", version: "1.0.0"},
          {name: "mango", version: "1.0.0"},
          {name: "apple", version: "1.0.0"}
        ]
        allow(Gems).to(receive_messages(
          versions: [{"number" => "1.0.0", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z"}],
          info: {"homepage_uri" => nil, "source_code_uri" => nil}
        ))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
      end

      it("returns gems in a deterministic, name-sorted order") do
        expect(result.keys).to(eq(["apple", "mango", "zebra"]))
      end
    end

    context("when --alternatives is enabled and a gem is archived") do
      before do
        StillActive.config.gems = [{name: "paperclip", version: "6.0.0"}]
        StillActive.config.alternatives = true
        allow(Gems).to(receive(:versions).with("paperclip").and_return([
          {"number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z", "licenses" => ["MIT"]}
        ]))
        allow(Gems).to(receive(:info).with("paperclip").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive(:repo_signals).and_return({archived: true, last_commit_date: nil}))
        allow(StillActive::CatalogIndex).to(receive(:load).and_return({"paperclip" => ["shrine", "carrierwave"]}))
        allow(StillActive::AlternativesHelper).to(receive(:leads_for).and_return(["shrine", "carrierwave"]))
      end

      it("sets alternatives on the archived gem") do
        expect(result["paperclip"][:alternatives]).to(eq(["shrine", "carrierwave"]))
      end
    end

    context("when an archived gem is transitive (#60: alternatives stay direct-only)") do
      before do
        StillActive.config.gems = [{name: "paperclip", version: "6.0.0", direct: false, dependency_path: ["rails", "paperclip"]}]
        StillActive.config.alternatives = true
        allow(Gems).to(receive(:versions).with("paperclip").and_return([
          {"number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z", "licenses" => ["MIT"]}
        ]))
        allow(Gems).to(receive(:info).with("paperclip").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive(:repo_signals).and_return({archived: true, last_commit_date: nil}))
        allow(StillActive::CatalogIndex).to(receive(:load).and_return({"paperclip" => ["shrine", "carrierwave"]}))
        allow(StillActive::AlternativesHelper).to(receive(:leads_for).and_return(["shrine", "carrierwave"]))
      end

      it("does not suggest alternatives for a transitive gem, but records the path to the direct parent") do
        expect(result["paperclip"]).not_to(have_key(:alternatives))
        expect(result["paperclip"][:direct]).to(be(false))
        expect(result["paperclip"][:dependency_path]).to(eq(["rails", "paperclip"]))
      end
    end

    context("when --alternatives is enabled but the catalog has no entry for the gem") do
      before do
        StillActive.config.gems = [{name: "paperclip", version: "6.0.0"}]
        StillActive.config.alternatives = true
        allow(Gems).to(receive(:versions).with("paperclip").and_return([
          {"number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z", "licenses" => ["MIT"]}
        ]))
        allow(Gems).to(receive(:info).with("paperclip").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive(:repo_signals).and_return({archived: true, last_commit_date: nil}))
        allow(StillActive::CatalogIndex).to(receive(:load).and_return({}))
      end

      it("leaves no alternatives key (silent on miss)") do
        expect(result["paperclip"]).not_to(have_key(:alternatives))
      end
    end

    context("when --alternatives is disabled") do
      before do
        StillActive.config.gems = [{name: "paperclip", version: "6.0.0"}]
        StillActive.config.alternatives = false
        allow(Gems).to(receive(:versions).with("paperclip").and_return([
          {"number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z"}
        ]))
        allow(Gems).to(receive(:info).with("paperclip").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive(:repo_signals).and_return({archived: true, last_commit_date: nil}))
        allow(StillActive::CatalogIndex).to(receive(:load))
      end

      it("does not load the catalog or set alternatives") do
        expect(result["paperclip"]).not_to(have_key(:alternatives))
        expect(StillActive::CatalogIndex).not_to(have_received(:load))
      end
    end

    context("with a poison-pill / compatibility ceiling") do
      # A dormant gem (last release 2016 -> critical) locked at 1.1.4.
      def stub_dormant_gem(name)
        allow(Gems).to(receive(:versions).with(name).and_return([
          {"number" => "1.1.4", "prerelease" => false, "created_at" => "2016-01-01T00:00:00Z", "licenses" => ["MIT"]}
        ]))
        allow(Gems).to(receive(:info).with(name).and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
      end

      before do
        StillActive.config.gems = [{name: "protected_attributes", version: "1.1.4"}]
        stub_dormant_gem("protected_attributes")
        # activemodel is at v8, so a "< 5.0" cap is 4 majors behind.
        allow(Gems).to(receive(:versions).with("activemodel").and_return([
          {"number" => "8.0.1", "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z"}
        ]))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive(:repo_signals).and_return({}))
      end

      it("attaches the constraint receipt and marks a below-latest ceiling as poison") do
        allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([
          {package_name: "activemodel", requirements: "< 5.0, >= 4.0.1"}
        ]))

        data = result["protected_attributes"]
        expect(data[:poison]).to(be(true))
        expect(data[:poison_severity]).to(eq(:critical)) # 4 majors behind
        expect(data[:constraints]).to(eq([
          {dependency: "activemodel", requirement: "< 5.0, >= 4.0.1", dep_latest: "8.0.1", majors_behind: 4, kind: :ceiling}
        ]))
      end

      it("does NOT flag a maintained gem's cap, and never even asks for its constraints (the discipline)") do
        StillActive.config.gems = [{name: "activerecord", version: "8.0.0"}]
        allow(Gems).to(receive(:versions).with("activerecord").and_return([
          {"number" => "8.0.0", "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z", "licenses" => ["MIT"]}
        ]))
        allow(Gems).to(receive(:info).with("activerecord").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
        allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies))

        data = result["activerecord"]
        expect(data).not_to(have_key(:poison))
        expect(data).not_to(have_key(:constraints))
        expect(StillActive::EcosystemsClient).not_to(have_received(:declared_dependencies))
      end

      it("does NOT flag a dormant gem whose runtime dep is permissive (nose/kaminari case)") do
        allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([
          {package_name: "activemodel", requirements: ">= 4.0.1"}
        ]))

        data = result["protected_attributes"]
        expect(data).not_to(have_key(:poison))
        expect(data).not_to(have_key(:constraints))
      end

      it("does NOT flag a dormant gem whose cap is at or above the dep's latest major") do
        allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([
          {package_name: "activemodel", requirements: "~> 8.0"}
        ]))

        expect(result["protected_attributes"]).not_to(have_key(:constraints))
      end

      it("surfaces a below-latest exact-pin as a hazard, but does not label it poison") do
        allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([
          {package_name: "activemodel", requirements: "= 4.2.0"}
        ]))

        data = result["protected_attributes"]
        expect(data[:poison]).to(be(false))
        expect(data[:constraints]).to(eq([
          {dependency: "activemodel", requirement: "= 4.2.0", dep_latest: "8.0.1", majors_behind: 4, kind: :exact_pin}
        ]))
      end

      it("drops a capped dep whose latest version can't be resolved, rather than guessing") do
        allow(Gems).to(receive(:versions).with("activemodel").and_return([]))
        allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([
          {package_name: "activemodel", requirements: "< 5.0"}
        ]))

        expect(result["protected_attributes"]).not_to(have_key(:constraints))
      end

      it("drops a capped dep when its latest lookup is rate-limited (Gems::GemError), leaving the dormant gem's own signals intact") do
        # A 429 on the extra dep lookup the poison path adds must degrade to "no
        # constraints", never crash the gem or blame it for an unrelated failure.
        allow(Gems).to(receive(:versions).with("activemodel").and_raise(Gems::GemError.new("429 Too Many Requests")))
        allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([
          {package_name: "activemodel", requirements: "< 5.0"}
        ]))

        data = result["protected_attributes"]
        expect(data).not_to(have_key(:constraints))
        expect(data[:latest_version]).to(eq("1.1.4"))
      end
    end

    context("with a language-runtime ceiling") do
      let(:range) do
        {
          oldest_supported: Gem::Version.new("3.3"),
          latest_stable: Gem::Version.new("4.0.5"),
          cycles: [
            {version: Gem::Version.new("4.0"), eol: false, eol_date: Time.parse("2029-03-31")},
            {version: Gem::Version.new("3.4"), eol: false, eol_date: Time.parse("2028-03-31")},
            {version: Gem::Version.new("3.3"), eol: false, eol_date: Time.parse("2027-03-31")},
            {version: Gem::Version.new("3.1"), eol: true, eol_date: Time.parse("2025-03-31")}
          ]
        }
      end

      before do
        allow(StillActive::RubyHelper).to(receive(:supported_ruby_range).and_return(range))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive(:repo_signals).and_return({}))
      end

      # A maintained gem pinned at an old version whose ruby_version caps the
      # runtime. NOT dormant: the ceiling is a compatibility fact regardless of
      # maintenance, unlike poison. latest (4.0.0) lifts the cap.
      def stub_gem_with_ruby_caps(name:, used:, used_ruby:, latest:, latest_ruby:)
        allow(Gems).to(receive(:versions).with(name).and_return([
          {"number" => latest, "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z", "licenses" => ["MIT"], "ruby_version" => latest_ruby},
          {"number" => used, "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z", "licenses" => ["MIT"], "ruby_version" => used_ruby}
        ]))
        allow(Gems).to(receive(:info).with(name).and_return({"homepage_uri" => nil, "source_code_uri" => nil}))
      end

      it("flags an EOL-forcing cap (critical) and notes that upgrading the gem lifts it") do
        StillActive.config.gems = [{name: "cfpropertylist", version: "3.0.9"}]
        stub_gem_with_ruby_caps(name: "cfpropertylist", used: "3.0.9", used_ruby: "< 3.2", latest: "4.0.0", latest_ruby: ">= 3.2")

        ceiling = result["cfpropertylist"][:language_ceiling]
        expect(ceiling[:runtime]).to(eq("Ruby"))
        expect(ceiling[:eol_forced]).to(be(true))
        expect(ceiling[:severity]).to(eq(:critical))
        expect(ceiling[:ceiling_version]).to(eq("3.1"))
        expect(ceiling[:fixed_by_upgrade]).to(be(true))
      end

      it("does not project the latest version's ceiling onto a pinned-but-yanked version we can't actually read") do
        StillActive.config.gems = [{name: "yankedcap", version: "0.9.0"}]
        # 0.9.0 is gone from the registry (yanked); only latest 2.0.0 remains, and it
        # caps ruby_version. Attaching 2.0.0's ceiling to the yanked 0.9.0 would be a
        # false attribution -- we have no idea what 0.9.0's ruby_version was.
        allow(Gems).to(receive(:versions).with("yankedcap").and_return([
          {"number" => "2.0.0", "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z", "licenses" => ["MIT"], "ruby_version" => "< 3.2"}
        ]))
        allow(Gems).to(receive(:info).with("yankedcap").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))

        expect(result["yankedcap"][:version_yanked]).to(be(true))
        expect(result["yankedcap"]).not_to(have_key(:language_ceiling))
      end

      it("flags a compound floor+ceiling ruby_version end-to-end (the real registry shape)") do
        StillActive.config.gems = [{name: "legacygem", version: "1.0.0"}]
        stub_gem_with_ruby_caps(name: "legacygem", used: "1.0.0", used_ruby: ">= 2.3.0, < 3.2", latest: "2.0.0", latest_ruby: ">= 3.3")

        ceiling = result["legacygem"][:language_ceiling]
        expect(ceiling[:eol_forced]).to(be(true))
        expect(ceiling[:severity]).to(eq(:critical))
        expect(ceiling[:ceiling_version]).to(eq("3.1"))
        expect(ceiling[:fixed_by_upgrade]).to(be(true))
      end

      it("flags a latest-not-yet cap on the resolved version as a note") do
        StillActive.config.gems = [{name: "somegem", version: "1.0.0"}]
        stub_gem_with_ruby_caps(name: "somegem", used: "1.0.0", used_ruby: "~> 3.3", latest: "1.0.0", latest_ruby: "~> 3.3")

        ceiling = result["somegem"][:language_ceiling]
        expect(ceiling[:eol_forced]).to(be(false))
        expect(ceiling[:severity]).to(eq(:note))
        expect(ceiling[:fixed_by_upgrade]).to(be(false))
      end

      it("reads the canonical `ruby`-platform ruby_version, not a precompiled native variant's tighter cap") do
        # Native gems ship a permissive `ruby` (source) platform plus precompiled
        # per-platform variants that cap ruby_version to the ABIs they were built
        # for. The source platform is the gem's true Ruby support, so a permissive
        # `ruby` entry must win even when a capped native entry is listed first.
        StillActive.config.gems = [{name: "sqlite3", version: "2.8.1"}]
        allow(Gems).to(receive(:versions).with("sqlite3").and_return([
          {"number" => "2.8.1", "platform" => "x86_64-linux", "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z", "licenses" => ["MIT"], "ruby_version" => ">= 3.1, < 3.5.dev"},
          {"number" => "2.8.1", "platform" => "ruby", "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z", "licenses" => ["MIT"], "ruby_version" => ">= 3.1"}
        ]))
        allow(Gems).to(receive(:info).with("sqlite3").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))

        expect(result["sqlite3"]).not_to(have_key(:language_ceiling))
      end

      it("does NOT flag a pinned version that declares no ruby_version, even if the latest version caps") do
        # Absent ruby_version means "runs on any Ruby" -> no ceiling. The cap on a
        # newer release must not be projected back onto the version in the tree.
        StillActive.config.gems = [{name: "oldgem", version: "1.0.0"}]
        allow(Gems).to(receive(:versions).with("oldgem").and_return([
          {"number" => "2.0.0", "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z", "licenses" => ["MIT"], "ruby_version" => "< 3.2"},
          {"number" => "1.0.0", "prerelease" => false, "created_at" => "2026-01-01T00:00:00Z", "licenses" => ["MIT"]} # no ruby_version
        ]))
        allow(Gems).to(receive(:info).with("oldgem").and_return({"homepage_uri" => nil, "source_code_uri" => nil}))

        expect(result["oldgem"]).not_to(have_key(:language_ceiling))
      end

      it("attaches nothing when the used version's ruby_version is a bare floor") do
        StillActive.config.gems = [{name: "modern", version: "2.0.0"}]
        stub_gem_with_ruby_caps(name: "modern", used: "2.0.0", used_ruby: ">= 3.1", latest: "2.0.0", latest_ruby: ">= 3.1")

        expect(result["modern"]).not_to(have_key(:language_ceiling))
      end

      it("attaches nothing when the Ruby support window is unavailable (range nil)") do
        allow(StillActive::RubyHelper).to(receive(:supported_ruby_range).and_return(nil))
        StillActive.config.gems = [{name: "cfpropertylist", version: "3.0.9"}]
        stub_gem_with_ruby_caps(name: "cfpropertylist", used: "3.0.9", used_ruby: "< 3.2", latest: "4.0.0", latest_ruby: ">= 3.2")

        expect(result["cfpropertylist"]).not_to(have_key(:language_ceiling))
      end
    end

    context("when configured to use gems with versions") do
      let(:gems) { ["rails", "nokogiri"] }
      let(:versions) { ["6.1.3.2", "1.12.5"] }
      let(:hash_keys) { [:name, :version] }

      before { StillActive.config.gems = gems.zip(versions).map { |info| hash_keys.zip(info).to_h } }

      it("returns a hash containing information about gems") do
        VCR.use_cassette("gems_with_versions") do
          expect(result).to(include(**{
            "rails" => hash_including(
              version_used: "6.1.3.2",
              latest_version: "8.1.2",
              # 8.1.0.rc1 predates the shipped 8.1.2, so it is dropped as noise.
              latest_pre_release_version: nil,
              repository_url: "https://github.com/rails/rails",
              ruby_gems_url: "https://rubygems.org/gems/rails",
              up_to_date: false,
              scorecard_score: a_value > 0,
              vulnerability_count: an_instance_of(Integer),
              license: "MIT"
            ),
            "nokogiri" => hash_including(
              version_used: "1.12.5",
              latest_version: "1.19.1",
              # 1.18.0.rc1 predates the shipped 1.19.1, so it is dropped as noise.
              latest_pre_release_version: nil,
              repository_url: "https://github.com/sparklemotion/nokogiri",
              ruby_gems_url: "https://rubygems.org/gems/nokogiri",
              up_to_date: false,
              scorecard_score: a_value > 0,
              vulnerability_count: an_instance_of(Integer)
            )
          }))
        end
      end
    end
  end

  describe(".versions") do
    before { allow(Gems).to(receive(:versions).and_return([{"number" => "9.9.9"}])) }

    it("queries public rubygems for a gem from the public source") do
      result = described_class.send(:versions, gem_name: "rake", source_uri: "https://rubygems.org/")

      expect(result).to(eq([{"number" => "9.9.9"}]))
      expect(Gems).to(have_received(:versions).with("rake"))
    end

    it("queries public rubygems when no source is known (e.g. --gems mode)") do
      described_class.send(:versions, gem_name: "rake", source_uri: nil)

      expect(Gems).to(have_received(:versions).with("rake"))
    end

    it("audits a direct private source that speaks the compact index, instead of giving up") do
      # Contribsys/Gemstash/Gemfury all serve the RubyGems compact index (it is how
      # `bundle install` resolves from them), so the agnostic rail covers them with no
      # per-host client. Previously these returned nothing.
      stub_request(:get, "https://gems.contribsys.com/info/sidekiq-pro")
        .to_return(status: 200, body: "---\n8.1.4 |checksum:aa\n8.1.5 |checksum:bb\n")

      result = described_class.send(:versions, gem_name: "sidekiq-pro", source_uri: "https://gems.contribsys.com/")

      expect(result.map { |h| h["number"] }).to(eq(["8.1.5", "8.1.4"]))
      expect(Gems).not_to(have_received(:versions))
    end

    it("falls through to the unqueryable warning when a private source serves no compact index") do
      stub_request(:get, "https://gems.internal.example.com/info/internalgem").to_return(status: 404)

      result = nil
      expect do
        result = described_class.send(:versions, gem_name: "internalgem", source_uri: "https://gems.internal.example.com/")
      end.to(output(/private source/i).to_stderr)

      expect(result).to(eq([]))
      expect(Gems).not_to(have_received(:versions))
    end

    it("never sends still_active's ambient Artifactory token to a lockfile-named private host") do
      # The ambient --artifactory-token is not host-keyed, so it must never ride the
      # generic private-source path to a host derived from the lockfile. Only Bundler's
      # own host-keyed credential may, and there is none here.
      StillActive.config.artifactory_token = "ambient-secret"
      allow(Bundler.settings).to(receive(:credentials_for).and_return(nil))
      stub_request(:get, "https://gems.contribsys.com/info/sidekiq-pro").to_return(status: 404)

      described_class.send(:versions, gem_name: "sidekiq-pro", source_uri: "https://gems.contribsys.com/")

      expect(WebMock).to(have_requested(:get, "https://gems.contribsys.com/info/sidekiq-pro")
        .with { |req| !req.headers.key?("Authorization") })
    end

    it("sends the source host's Bundler credential on the compact-index request") do
      allow(Bundler.settings).to(receive(:credentials_for)) { |uri| (uri.host == "gems.contribsys.com") ? "sub:key" : nil }
      stub_request(:get, "https://gems.contribsys.com/info/sidekiq-pro")
        .to_return(status: 200, body: "---\n8.1.5 |checksum:bb\n")

      described_class.send(:versions, gem_name: "sidekiq-pro", source_uri: "https://gems.contribsys.com/")

      expect(WebMock).to(have_requested(:get, "https://gems.contribsys.com/info/sidekiq-pro")
        .with(headers: {"Authorization" => "Basic #{["sub:key"].pack("m0")}"}))
    end

    it("treats rubygems.org subdomains as public") do
      described_class.send(:versions, gem_name: "rake", source_uri: "https://index.rubygems.org/")

      expect(Gems).to(have_received(:versions).with("rake"))
    end

    it("treats an uppercase RubyGems.org host as public (hostnames are case-insensitive)") do
      described_class.send(:versions, gem_name: "rake", source_uri: "https://RubyGems.org/")

      expect(Gems).to(have_received(:versions).with("rake"))
    end

    it("treats a trailing-dot FQDN rubygems.org host as public") do
      described_class.send(:versions, gem_name: "rake", source_uri: "https://rubygems.org./")

      expect(Gems).to(have_received(:versions).with("rake"))
    end

    it("degrades to [] (never raising) when rubygems.org rate-limits or 5xxs (Gems::GemError)") do
      # The `gems` library raises Gems::GemError for any non-success, non-404
      # response. Unrescued it would escape #versions and strip the gem of every
      # signal via the per-gem rescue in #call, not just its version list.
      allow(Gems).to(receive(:versions).with("flaky").and_raise(Gems::GemError.new("429 Too Many Requests")))

      result = nil
      expect { result = described_class.send(:versions, gem_name: "flaky", source_uri: nil) }
        .to(output(/versions lookup failed.*Gems::GemError/).to_stderr)
      expect(result).to(eq([]))
    end
  end

  describe("#provider_for (GitHub repo-signal source selection)") do
    it("uses the live GitHub client when a token is configured") do
      StillActive.config.github_oauth_token = "ghp_test_token"
      expect(described_class.send(:provider_for, :github)).to(be(StillActive::GithubClient))
    end

    it("falls back to ecosyste.ms when no GitHub token is available (avoids the 60 req/hr cap)") do
      allow(StillActive.config).to(receive(:github_oauth_token).and_return(nil))
      expect(described_class.send(:provider_for, :github)).to(be(StillActive::EcosystemsClient))
    end

    it("still uses the GitLab client for gitlab sources regardless of GitHub token") do
      allow(StillActive.config).to(receive(:github_oauth_token).and_return(nil))
      expect(described_class.send(:provider_for, :gitlab)).to(be(StillActive::GitlabClient))
    end
  end

  describe(".repository_info") do
    before { allow(Gems).to(receive(:info).and_return({"homepage_uri" => nil, "source_code_uri" => nil})) }

    it("does not consult public rubygems.org metadata for an unqueryable private source") do
      described_class.send(:repository_info, gem_name: "internalgem_xyz", versions: [], source_uri: "https://gems.internal.example.com/")

      expect(Gems).not_to(have_received(:info))
    end

    it("keeps the #43 repo-URL guard even when the private source now yields versions") do
      # Auditing a private source's versions via the compact-index rail must not
      # unblock the public repo-URL substitution: the two guards are separate, both
      # keyed on unqueryable_private_source?, and a name collision's repo/archived
      # data must still never stand in for the private gem.
      versions = [{"number" => "8.1.5", "prerelease" => false}]
      described_class.send(:repository_info, gem_name: "sidekiq-pro", versions: versions, source_uri: "https://gems.contribsys.com/")

      expect(Gems).not_to(have_received(:info))
    end

    it("falls back to public rubygems.org metadata for a public-source gem") do
      described_class.send(:repository_info, gem_name: "publicgem_xyz", versions: [], source_uri: "https://rubygems.org/")

      expect(Gems).to(have_received(:info).with("publicgem_xyz"))
    end
  end

  describe(".resolve_latest_version (capped-dep latest resolution + per-run cache)") do
    it("reuses an in-tree dep's already-computed latest_version without a network call") do
      allow(Gems).to(receive(:versions))
      result_object = {"activemodel" => {latest_version: "8.0.1"}}

      latest = described_class.send(:resolve_latest_version, "activemodel", result_object: result_object, cache: {})

      expect(latest).to(eq("8.0.1"))
      expect(Gems).not_to(have_received(:versions))
    end

    it("fetches once and memoizes a dep not present in the tree") do
      allow(Gems).to(receive(:versions).with("terrapin").and_return([
        {"number" => "1.0.1", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z"}
      ]))
      cache = {}

      first = described_class.send(:resolve_latest_version, "terrapin", result_object: {}, cache: cache)
      second = described_class.send(:resolve_latest_version, "terrapin", result_object: {}, cache: cache)

      expect([first, second]).to(all(eq("1.0.1")))
      expect(Gems).to(have_received(:versions).with("terrapin").once)
    end

    it("re-attempts an unresolved dep rather than caching the miss, so a transient failure can't permanently suppress a later pill") do
      # First lookup: latest momentarily unavailable (rate-limit/timeout -> []).
      # Second: it resolves. Caching the first nil would drop the pill run-wide.
      allow(Gems).to(receive(:versions).with("flappy")
        .and_return([], [{"number" => "3.0.0", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z"}]))
      cache = {}

      first = described_class.send(:resolve_latest_version, "flappy", result_object: {}, cache: cache)
      second = described_class.send(:resolve_latest_version, "flappy", result_object: {}, cache: cache)

      expect(first).to(be_nil)
      expect(second).to(eq("3.0.0"))
    end
  end

  describe(".unreleased_commits dispatch") do
    it("delegates to GithubClient for a github source") do
      allow(StillActive::GithubClient).to(receive(:commits_since_release).with(owner: "rails", name: "rails", version: "7.0.1").and_return(5))
      result = described_class.send(:unreleased_commits, source: :github, repository_owner: "rails", repository_name: "rails", version: "7.0.1")
      expect(result).to(eq(5))
    end

    it("returns nil for a gitlab source, which does not implement the capability") do
      # GitLab has no scalar ahead_by; it must not be assumed to support the signal.
      expect(StillActive::GitlabClient).not_to(respond_to(:commits_since_release))
      expect(described_class.send(:unreleased_commits, source: :gitlab, repository_owner: "g", repository_name: "g", version: "1.0")).to(be_nil)
    end

    it("returns nil for a forgejo source, which does not implement the capability") do
      expect(StillActive::ForgejoClient).not_to(respond_to(:commits_since_release))
      expect(described_class.send(:unreleased_commits, source: :forgejo, repository_owner: "f", repository_name: "f", version: "1.0")).to(be_nil)
    end

    it("returns nil for an unhandled source without raising") do
      expect(described_class.send(:unreleased_commits, source: :unhandled, repository_owner: nil, repository_name: nil, version: nil)).to(be_nil)
    end
  end

  describe("#call with --unreleased-commits") do
    before do
      StillActive.config.unreleased_commits = true
      StillActive.config.gems = [{name: "rails"}]
    end

    it("merges the unreleased_commits count into the gem entry") do
      allow(described_class).to(receive(:unreleased_commits).and_return(17))
      VCR.use_cassette("gems") do
        expect(described_class.call["rails"]).to(include(unreleased_commits: 17))
      end
    end

    it("does not set the key when the flag is off") do
      StillActive.config.unreleased_commits = false
      VCR.use_cassette("gems") do
        expect(described_class.call["rails"]).not_to(have_key(:unreleased_commits))
      end
    end
  end

  describe(".repository_info_for_non_rubygems") do
    it("builds a deps.dev project_id for a github-hosted source") do
      info = described_class.send(:repository_info_for_non_rubygems, gem_name: "ghgem_xyz", source_uri: "https://github.com/owner/ghgem_xyz")

      expect(info).to(include(source: :github, project_id: "github.com/owner/ghgem_xyz"))
    end

    it("leaves project_id nil for a codeberg/forgejo source deps.dev does not index") do
      info = described_class.send(:repository_info_for_non_rubygems, gem_name: "cbgem_xyz", source_uri: "https://codeberg.org/owner/cbgem_xyz")

      expect(info).to(include(source: :forgejo, project_id: nil))
    end
  end
end
