# frozen_string_literal: true

RSpec.describe(StillActive::Repository) do
  let(:valid_github_urls) do
    [
      "https://github.com/seanlf/still_active",
      "https://github.com/seanlf/still_active/blob/master/lib",
    ]
  end
  let(:valid_gitlab_urls) do
    [
      "https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/graphql/types/query_type.rb",
      "https://gitlab.com/gitlab-org/gitlab/",
    ]
  end
  let(:valid_urls) do
    [valid_github_urls, valid_gitlab_urls].flatten
  end

  describe("#valid?") do
    context("for valid URLs") do
      it("returns valid") do
        valid_urls.each do |url|
          subject = described_class.valid?(url: url)
          expect(subject).to(be_truthy)
        end
      end
    end

    context("for invalid URLs") do
      subject { described_class.valid?(url: Faker::Internet.url) }
      it("returns invalid") do
        expect(subject).to(be_falsy)
      end
    end
  end

  describe("#url_with_owner_and_name") do
    context("for valid URLs") do
      it("returns valid") do
        valid_github_urls.each do |url|
          subject = described_class.url_with_owner_and_name(url: url)
          expected_result = { source: "github", owner: "seanlf", name: "still_active" }
          expect(subject).to(include(expected_result))
        end

        valid_gitlab_urls.each do |url|
          subject = described_class.url_with_owner_and_name(url: url)
          expected_result = { source: "gitlab", owner: "gitlab-org", name: "gitlab" }
          expect(subject).to(include(expected_result))
        end
      end
    end

    context("for invalid URLs") do
      subject { described_class.url_with_owner_and_name(url: Faker::Internet.url) }
      let(:expected_result) { { source: :unhandled, owner: nil, name: nil } }
      it("returns invalid") do
        expect(subject).to(include(expected_result))
      end
    end
  end
end
