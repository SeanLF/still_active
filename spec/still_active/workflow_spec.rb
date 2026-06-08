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
  end

  describe("#call") do
    subject(:result) { described_class.call }

    context("when configured to use gems") do
      let(:gems) { ["rails", "nokogiri"] }

      before { StillActive.config.gems = gems.map { |name| { name: name } } }

      it("returns a hash containing information about gems") do
        VCR.use_cassette("gems") do
          expect(result).to(include(**{
            "rails" => hash_including(
              latest_version: "8.1.2",
              latest_pre_release_version: "8.1.0.rc1",
              repository_url: "https://github.com/rails/rails",
              ruby_gems_url: "https://rubygems.org/gems/rails",
              scorecard_score: a_value > 0,
              vulnerability_count: an_instance_of(Integer),
            ),
            "nokogiri" => hash_including(
              latest_version: "1.19.1",
              latest_pre_release_version: "1.18.0.rc1",
              repository_url: "https://github.com/sparklemotion/nokogiri",
              ruby_gems_url: "https://rubygems.org/gems/nokogiri",
              scorecard_score: a_value > 0,
              vulnerability_count: an_instance_of(Integer),
            ),
          }))
        end
      end
    end

    context("when ruby-advisory-db is available as a second source") do
      before do
        StillActive.config.gems = [{ name: "rack", version: "2.0.0" }]
        allow(Gems).to(receive(:versions).with("rack").and_return([
          { "number" => "2.0.0", "prerelease" => false, "created_at" => "2016-05-06T00:00:00Z", "licenses" => ["MIT"] },
        ]))
        allow(Gems).to(receive(:info).with("rack").and_return({ "homepage_uri" => nil, "source_code_uri" => nil }))
        allow(StillActive::DepsDevClient).to(receive_messages(
          version_info: { advisory_keys: ["GHSA-deps"], project_id: nil },
          project_scorecard: nil,
          advisory_detail: { id: "GHSA-deps", aliases: [], title: "from deps.dev", cvss3_score: 7.5, source: "deps.dev" },
        ))
        allow(StillActive::RubyAdvisoryDb).to(receive(:load).and_return(:fake_db))

        # rack's gemspec may already be activated by another spec, in which case
        # repository_info resolves a real github.com/rack/rack URL and the commit
        # lookup makes a live HTTP call (no cassette here) that propagates out and
        # discards the gem's entry. Pin the repo-derived fields so this context
        # exercises only the advisory merge, regardless of what's been activated.
        allow(described_class).to(receive_messages(last_commit_date: nil, repo_archived: nil))
      end

      it("appends advisories unique to ruby-advisory-db") do
        allow(StillActive::RubyAdvisoryDb).to(receive(:advisories_for).and_return(
          [{ id: "GHSA-radb", aliases: [], cvss3_score: 5.0, source: "ruby-advisory-db" }],
        ))

        data = result["rack"]
        expect(data[:vulnerability_count]).to(eq(2))
        expect(data[:vulnerabilities].map { |v| v[:source] }).to(contain_exactly("deps.dev", "ruby-advisory-db"))
      end

      it("deduplicates an advisory reported by both sources into one merged entry") do
        allow(StillActive::RubyAdvisoryDb).to(receive(:advisories_for).and_return(
          [{ id: "GHSA-deps", aliases: ["OSVDB-1"], cvss3_score: 6.0, source: "ruby-advisory-db" }],
        ))

        data = result["rack"]
        expect(data[:vulnerability_count]).to(eq(1))
        expect(data[:vulnerabilities].first).to(include(source: "merged", title: "from deps.dev", cvss3_score: 7.5))
      end
    end

    context("when a gem version is yanked") do
      before do
        StillActive.config.gems = [{ name: "yanked_gem", version: "0.9.0" }]

        # Gem exists but version 0.9.0 is not in the list (yanked)
        allow(Gems).to(receive(:versions).with("yanked_gem").and_return([
          { "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z" },
        ]))
        allow(Gems).to(receive(:info).with("yanked_gem").and_return({
          "homepage_uri" => nil,
          "source_code_uri" => nil,
        }))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
      end

      it("sets version_yanked to true") do
        expect(result).to(include(
          "yanked_gem" => hash_including(version_yanked: true),
        ))
      end
    end

    context("when a gem version is not yanked") do
      before do
        StillActive.config.gems = [{ name: "good_gem", version: "1.0.0" }]

        allow(Gems).to(receive(:versions).with("good_gem").and_return([
          { "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z" },
        ]))
        allow(Gems).to(receive(:info).with("good_gem").and_return({
          "homepage_uri" => nil,
          "source_code_uri" => nil,
        }))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
      end

      it("sets version_yanked to false") do
        expect(result).to(include(
          "good_gem" => hash_including(version_yanked: false),
        ))
      end
    end

    context("when a gem is git-sourced") do
      before do
        StillActive.config.gems = [{ name: "git_gem", version: "0.5.0", source_type: :git }]
        allow(Gems).to(receive(:versions))
        allow(StillActive::DepsDevClient).to(receive(:project_scorecard).and_return(nil))
      end

      it("does not query Gems.versions") do
        result
        expect(Gems).not_to(have_received(:versions))
      end

      it("sets source_type to :git") do
        expect(result).to(include(
          "git_gem" => hash_including(source_type: :git),
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
        StillActive.config.gems = [{ name: "path_gem", version: "0.1.0", source_type: :path }]
        allow(Gems).to(receive(:versions))
        allow(StillActive::DepsDevClient).to(receive(:project_scorecard).and_return(nil))
      end

      it("does not query Gems.versions") do
        result
        expect(Gems).not_to(have_received(:versions))
      end

      it("sets source_type to :path") do
        expect(result).to(include(
          "path_gem" => hash_including(source_type: :path),
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
          { "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-06-01T00:00:00Z" },
        ]
      end

      before do
        StillActive.config.gems = [{
          name: "private_gem",
          version: "1.0.0",
          source_type: :rubygems,
          source_uri: "https://rubygems.pkg.github.com/my-org",
        }]
        StillActive.config.github_oauth_token = "ghp_test_token"
        stub_request(:get, "https://rubygems.pkg.github.com/my-org/api/v1/gems/private_gem/versions.json")
          .to_return(status: 200, body: ghp_versions.to_json, headers: { "Content-Type" => "application/json" })
        allow(Gems).to(receive(:info).with("private_gem").and_return({
          "homepage_uri" => nil,
          "source_code_uri" => nil,
        }))
        allow(StillActive::DepsDevClient).to(receive(:version_info).and_return(nil))
      end

      it("fetches versions from GitHub Packages API") do
        result
        expect(WebMock).to(have_requested(:get, "https://rubygems.pkg.github.com/my-org/api/v1/gems/private_gem/versions.json")
          .with(headers: { "Authorization" => "Bearer ghp_test_token" }))
      end

      it("returns version data from GitHub Packages") do
        expect(result).to(include(
          "private_gem" => hash_including(latest_version: "1.0.0"),
        ))
      end
    end

    context("when a progress block is given") do
      before do
        StillActive.config.gems = [
          { name: "gem_a", version: "1.0.0" },
          { name: "gem_b", version: "2.0.0" },
          { name: "gem_c", version: "3.0.0" },
        ]
        allow(Gems).to(receive_messages(
          versions: [{ "number" => "1.0.0", "prerelease" => false, "created_at" => "2025-01-01T00:00:00Z" }],
          info: { "homepage_uri" => nil, "source_code_uri" => nil },
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

    context("when --alternatives is enabled and a gem is archived") do
      before do
        StillActive.config.gems = [{ name: "paperclip", version: "6.0.0" }]
        StillActive.config.alternatives = true
        allow(Gems).to(receive(:versions).with("paperclip").and_return([
          { "number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z", "licenses" => ["MIT"] },
        ]))
        allow(Gems).to(receive(:info).with("paperclip").and_return({ "homepage_uri" => nil, "source_code_uri" => nil }))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive_messages(repo_archived: true, last_commit_date: nil))
        allow(StillActive::CatalogIndex).to(receive(:load).and_return({ "paperclip" => ["shrine", "carrierwave"] }))
        allow(StillActive::AlternativesHelper).to(receive(:leads_for).and_return(["shrine", "carrierwave"]))
      end

      it("sets alternatives on the archived gem") do
        expect(result["paperclip"][:alternatives]).to(eq(["shrine", "carrierwave"]))
      end
    end

    context("when --alternatives is enabled but the catalog has no entry for the gem") do
      before do
        StillActive.config.gems = [{ name: "paperclip", version: "6.0.0" }]
        StillActive.config.alternatives = true
        allow(Gems).to(receive(:versions).with("paperclip").and_return([
          { "number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z", "licenses" => ["MIT"] },
        ]))
        allow(Gems).to(receive(:info).with("paperclip").and_return({ "homepage_uri" => nil, "source_code_uri" => nil }))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive_messages(repo_archived: true, last_commit_date: nil))
        allow(StillActive::CatalogIndex).to(receive(:load).and_return({}))
      end

      it("leaves no alternatives key (silent on miss)") do
        expect(result["paperclip"]).not_to(have_key(:alternatives))
      end
    end

    context("when --alternatives is disabled") do
      before do
        StillActive.config.gems = [{ name: "paperclip", version: "6.0.0" }]
        StillActive.config.alternatives = false
        allow(Gems).to(receive(:versions).with("paperclip").and_return([
          { "number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z" },
        ]))
        allow(Gems).to(receive(:info).with("paperclip").and_return({ "homepage_uri" => nil, "source_code_uri" => nil }))
        allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
        allow(described_class).to(receive_messages(repo_archived: true, last_commit_date: nil))
        allow(StillActive::CatalogIndex).to(receive(:load))
      end

      it("does not load the catalog or set alternatives") do
        expect(result["paperclip"]).not_to(have_key(:alternatives))
        expect(StillActive::CatalogIndex).not_to(have_received(:load))
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
              latest_pre_release_version: "8.1.0.rc1",
              repository_url: "https://github.com/rails/rails",
              ruby_gems_url: "https://rubygems.org/gems/rails",
              up_to_date: false,
              scorecard_score: a_value > 0,
              vulnerability_count: an_instance_of(Integer),
              license: "MIT",
            ),
            "nokogiri" => hash_including(
              version_used: "1.12.5",
              latest_version: "1.19.1",
              latest_pre_release_version: "1.18.0.rc1",
              repository_url: "https://github.com/sparklemotion/nokogiri",
              ruby_gems_url: "https://rubygems.org/gems/nokogiri",
              up_to_date: false,
              scorecard_score: a_value > 0,
              vulnerability_count: an_instance_of(Integer),
            ),
          }))
        end
      end
    end
  end
end
