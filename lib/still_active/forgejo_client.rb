# frozen_string_literal: true

require "time"
require_relative "../helpers/http_helper"

module StillActive
  # Repo signals (archived?, last commit date) for Forgejo/Gitea-hosted gems.
  # Codeberg.org is the only host wired into the workflow today, but every
  # Forgejo/Gitea instance speaks the same `/api/v1` surface, so the host is a
  # parameter for later self-hosted support. Mirrors GitlabClient: HttpHelper
  # against a documented JSON API, anonymous by default with an optional token.
  module ForgejoClient
    extend self

    DEFAULT_HOST = "codeberg.org"

    def archived(owner:, name:, host: DEFAULT_HOST)
      return if owner.nil? || name.nil?

      body = HttpHelper.get_json(base_uri(host), "/api/v1/repos/#{owner}/#{name}", headers: auth_headers)
      return if body.nil?

      body["archived"] == true
    end

    def last_commit_date(owner:, name:, host: DEFAULT_HOST)
      return if owner.nil? || name.nil?

      # stat/verification/files default on and pull per-commit diffs and GPG
      # checks we don't use; turn them off so a single-commit lookup stays cheap.
      params = { limit: 1, stat: false, verification: false, files: false }
      body = HttpHelper.get_json(base_uri(host), "/api/v1/repos/#{owner}/#{name}/commits", headers: auth_headers, params: params)
      return if body.nil? || body.empty?

      date = body.first.dig("commit", "committer", "date") || body.first.dig("commit", "author", "date")
      return unless date

      begin
        Time.parse(date)
      rescue ArgumentError
        $stderr.puts("warning: could not parse commit date for #{owner}/#{name}: #{date.inspect}")
        nil
      end
    end

    private

    def base_uri(host)
      URI("https://#{host}/")
    end

    def auth_headers
      token = StillActive.config.forgejo_token
      token ? { "Authorization" => "token #{token}" } : {}
    end
  end
end
