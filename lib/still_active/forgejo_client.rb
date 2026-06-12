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

    # archived + last-activity date from a single repository call. The repo
    # object's updated_at matches the latest commit date to the day in practice,
    # so folding the two signals into one call halves the per-gem requests.
    # Returns {} when the repo can't be read.
    def repo_signals(owner:, name:, host: DEFAULT_HOST)
      return {} if owner.nil? || name.nil?

      body = HttpHelper.get_json(base_uri(host), "/api/v1/repos/#{owner}/#{name}", headers: auth_headers)
      return {} if body.nil?

      { archived: body["archived"] == true, last_commit_date: parse_time(body["updated_at"], owner, name) }
    end

    private

    def parse_time(value, owner, name)
      return if value.nil?

      Time.parse(value)
    rescue ArgumentError
      $stderr.puts("warning: could not parse repo date for #{owner}/#{name}: #{value.inspect}")
      nil
    end

    def base_uri(host)
      URI("https://#{host}/")
    end

    def auth_headers
      token = StillActive.config.forgejo_token
      token ? { "Authorization" => "token #{token}" } : {}
    end
  end
end
