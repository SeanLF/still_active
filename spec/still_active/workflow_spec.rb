# frozen_string_literal: true

require "vcr"

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into(:webmock)
  config.filter_sensitive_data("<GITHUB_TOKEN>") { ENV.fetch("GITHUB_TOKEN", "") }
  config.filter_sensitive_data("<RUBYGEMS_API_KEY>") { ENV.fetch("RUBYGEMS_API_KEY", "") }
end

RSpec.describe(StillActive::Workflow) do
  describe("#call") do
    subject(:result) { described_class.call }

    context("when configured to use gems") do
      let(:gems) { ["rails", "nokogiri"] }

      before { StillActive.config.gems = gems.map { |name| { name: name } } }

      it("returns a hash containing information about gems") do
        VCR.use_cassette("gems") do
          expect(result).to(include(**{
            "rails" => {
              latest_version: "8.1.2",
              latest_version_release_date: Time.parse("2026-01-08 20:18:51.400 UTC"),
              latest_pre_release_version: "8.1.0.rc1",
              latest_pre_release_version_release_date: Time.parse("2025-10-15 00:52:14.096 UTC"),
              repository_url: "https://github.com/rails/rails",
              last_commit_date: Time.parse("2026-02-19 09:39:03 UTC"),
              ruby_gems_url: "https://rubygems.org/gems/rails",
            },
            "nokogiri" => {
              latest_version: "1.19.1",
              latest_version_release_date: Time.parse("2026-02-16 23:31:21.075 UTC"),
              latest_pre_release_version: "1.18.0.rc1",
              latest_pre_release_version_release_date: Time.parse("2024-12-16 17:48:44.371 UTC"),
              repository_url: "https://github.com/sparklemotion/nokogiri",
              last_commit_date: Time.parse("2026-02-17 19:13:22 UTC"),
              ruby_gems_url: "https://rubygems.org/gems/nokogiri",
            },
          }))
        end
      end
    end

    context("when configured to use gems with versions") do
      let(:gems) { ["rails", "nokogiri"] }
      let(:versions) { ["6.1.3.2", "1.12.5"] }
      let(:hash_keys) { [:name, :version] }

      before { StillActive.config.gems = gems.zip(versions).map { |info| hash_keys.zip(info).to_h } }

      it("returns a hash containing information about gems") do
        VCR.use_cassette("gems") do
          expect(result).to(include(**{
            "rails" => {
              version_used: "6.1.3.2",
              latest_version: "8.1.2",
              latest_version_release_date: Time.parse("2026-01-08 20:18:51.400 UTC"),
              latest_pre_release_version: "8.1.0.rc1",
              latest_pre_release_version_release_date: Time.parse("2025-10-15 00:52:14.096 UTC"),
              repository_url: "https://github.com/rails/rails",
              last_commit_date: Time.parse("2026-02-19 09:39:03 UTC"),
              ruby_gems_url: "https://rubygems.org/gems/rails",
              up_to_date: false,
              version_used_release_date: Time.parse("2021-05-05 15:47:12.17 UTC"),
            },
            "nokogiri" => {
              version_used: "1.12.5",
              latest_version: "1.19.1",
              latest_version_release_date: Time.parse("2026-02-16 23:31:21.075 UTC"),
              latest_pre_release_version: "1.18.0.rc1",
              latest_pre_release_version_release_date: Time.parse("2024-12-16 17:48:44.371 UTC"),
              repository_url: "https://github.com/sparklemotion/nokogiri",
              last_commit_date: Time.parse("2026-02-17 19:13:22 UTC"),
              ruby_gems_url: "https://rubygems.org/gems/nokogiri",
              up_to_date: false,
              version_used_release_date: Time.parse("2021-09-27 19:03:57.243 UTC"),
            },
          }))
        end
      end
    end
  end
end
