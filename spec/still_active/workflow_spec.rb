# frozen_string_literal: true

require "vcr"

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into(:webmock)
end

RSpec.describe(StillActive::Workflow) do
  describe("#call") do
    subject { described_class.call }

    context("when configured to use gems") do
      let(:gems) { ["rails", "nokogiri"] }

      before { StillActive.config.gems = gems.map { |name| { name: name } } }

      it("returns a hash containing information about gems") do
        VCR.use_cassette("gems") do
          expect(subject).to(include(**{
            "rails" => {
              latest_version: "6.1.4.1",
              latest_version_release_date: Time.parse("2021-08-19 16:27:05.901 UTC"),
              latest_pre_release_version: "7.0.0.alpha2",
              latest_pre_release_version_release_date: Time.parse("2021-09-15 23:16:26.58 UTC"),
              repository_url: "https://github.com/rails/rails",
              last_commit_date: Time.parse("2021-11-10 09:05:18 UTC"),
              ruby_gems_url: "https://rubygems.org/gems/rails",
            },
            "nokogiri" => {
              latest_version: "1.12.5",
              latest_version_release_date: Time.parse("2021-09-27 19:03:57.243 UTC"),
              latest_pre_release_version: "1.12.0.rc1",
              latest_pre_release_version_release_date: Time.parse("2021-07-09 20:00:11.917 UTC"),
              repository_url: "https://github.com/sparklemotion/nokogiri",
              last_commit_date: Time.parse("2021-11-06 16:44:55 UTC"),
              ruby_gems_url: "https://rubygems.org/gems/nokogiri",
            },
          }))
        end
      end
    end

    context("when configured to use gems with versions") do
      let(:gems) { ["rails", "nokogiri"] }
      let(:versions) { ["6.1.3.2", "1.12.5"] }

      before { StillActive.config.gems = gems.zip(versions).map { |info| [:name, :version].zip(info).to_h } }

      it("returns a hash containing information about gems") do
        VCR.use_cassette("gems") do
          expect(subject).to(include(**{
            "rails" => {
              version_used: "6.1.3.2",
              latest_version: "6.1.4.1",
              latest_version_release_date: Time.parse("2021-08-19 16:27:05.901 UTC"),
              latest_pre_release_version: "7.0.0.alpha2",
              latest_pre_release_version_release_date: Time.parse("2021-09-15 23:16:26.58 UTC"),
              repository_url: "https://github.com/rails/rails",
              last_commit_date: Time.parse("2021-11-10 09:05:18 UTC"),
              ruby_gems_url: "https://rubygems.org/gems/rails",
              up_to_date: false,
              version_used_release_date: Time.parse("2021-05-05 15:47:12.17 UTC"),
            },
            "nokogiri" => {
              version_used: "1.12.5",
              latest_version: "1.12.5",
              latest_version_release_date: Time.parse("2021-09-27 19:03:57.243 UTC"),
              latest_pre_release_version: "1.12.0.rc1",
              latest_pre_release_version_release_date: Time.parse("2021-07-09 20:00:11.917 UTC"),
              repository_url: "https://github.com/sparklemotion/nokogiri",
              last_commit_date: Time.parse("2021-11-06 16:44:55 UTC"),
              ruby_gems_url: "https://rubygems.org/gems/nokogiri",
              up_to_date: true,
              version_used_release_date: Time.parse("2021-09-27 19:03:57.243 UTC"),
            },
          }))
        end
      end
    end
  end
end
