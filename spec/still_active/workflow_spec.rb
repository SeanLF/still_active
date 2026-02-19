# frozen_string_literal: true

RSpec.describe(StillActive::Workflow) do
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

    context("when configured to use gems with versions") do
      let(:gems) { ["rails", "nokogiri"] }
      let(:versions) { ["6.1.3.2", "1.12.5"] }
      let(:hash_keys) { [:name, :version] }

      before { StillActive.config.gems = gems.zip(versions).map { |info| hash_keys.zip(info).to_h } }

      it("returns a hash containing information about gems") do
        VCR.use_cassette("gems") do
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
