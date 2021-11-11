# frozen_string_literal: true

module StillActive
  module Repository
    GITHUB_REGEX = %r{(http(?:s)?://(?:www\.)?(github)\.com/((?:\w|_|-)+)/((?:\w|_|-)+))}i
    GITLAB_REGEX = %r{(http(?:s)?://(?:www\.)?(gitlab)\.com/((?:\w|_|-)+)/((?:\w|_|-)+))}i

    HASH_KEYS = [:url, :source, :owner, :name]
    private_constant :HASH_KEYS

    extend self

    def valid?(url:)
      [GITHUB_REGEX, GITLAB_REGEX].any? do |regex|
        !url.scan(regex)&.first.nil?
      end
    end

    def url_with_owner_and_name(url:)
      [GITHUB_REGEX, GITLAB_REGEX].each do |regex|
        values = url&.scan(regex)&.first
        next if values.nil? || values.empty?

        return HASH_KEYS.zip(values).to_h
      end
      { source: :unhandled, owner: nil, name: nil }
    end
  end
end
