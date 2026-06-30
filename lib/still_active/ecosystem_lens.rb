# frozen_string_literal: true

require_relative "deps_dev_client"
require_relative "ecosystems_client"
require_relative "github_client"
require_relative "../helpers/vulnerability_helper"

module StillActive
  # The cross-ecosystem maintenance lens. Given one SBOM-derived dependency
  # ({ecosystem, name, version}), it assembles the same maintenance signals the
  # native Ruby path produces -- latest release date, archived, advisories,
  # scorecard -- into a gem_data hash StatusHelper.gem_status can read directly.
  # The breadth counterpart to the depth Bundler path gives Ruby.
  #
  # Security: the SBOM supplies only ecosystem/name/version. The repository is
  # discovered from deps.dev (a public source still_active opts into), never from
  # a lockfile-derived URL, so a hostile SBOM can't redirect a lookup. Anything
  # unresolvable (a private package deps.dev doesn't index) degrades to nil
  # signals -> :unknown, never a fabricated "ok".
  module EcosystemLens
    extend self

    def assess(ecosystem:, name:, version:)
      info = DepsDevClient.version_info(gem_name: name, version: version, system: ecosystem)
      default = DepsDevClient.default_version_info(name: name, system: ecosystem)
      # Recover the repo from the default version when the exact locked version
      # isn't indexed (yanked/normalization mismatch): otherwise its project link
      # vanishes and a still-fresh package date would read a false :ok with
      # archived/scorecard silently dropped. The native Bundler path resolves the
      # repo independently of deps.dev's per-version record; this gives the lens
      # the same resilience.
      project_id = info&.dig(:project_id) || project_id_from(name, ecosystem, default)
      vulnerabilities = vulnerabilities_for(info)
      scorecard = DepsDevClient.project_scorecard(project_id: project_id)
      repo = repo_signals(project_id)

      {
        ecosystem: ecosystem,
        name: name,
        version_used: version,
        latest_version_release_date: default&.dig(:published_at),
        repository_url: project_id && "https://#{project_id}",
        last_commit_date: repo[:last_commit_date],
        archived: repo[:archived],
        scorecard_score: scorecard&.dig(:score),
        scorecard_maintained: scorecard&.dig(:maintained),
        vulnerability_count: vulnerabilities.length,
        vulnerabilities: vulnerabilities,
      }
    end

    private

    def vulnerabilities_for(info)
      advisory_keys = info&.dig(:advisory_keys) || []
      # The keys ARE the evidence the locked version is vulnerable; the detail
      # fetch only enriches CVSS/title. A failed enrichment must not drop the
      # count to zero and read a known-vulnerable dep as clean, so a key whose
      # detail can't be loaded still contributes a minimal advisory.
      deps_dev = advisory_keys.map { DepsDevClient.advisory_detail(advisory_id: _1) || { id: _1, source: "deps.dev" } }
      # No ruby-advisory-db here: that database is Ruby-only and the native
      # Bundler path already merges it. Cross-ecosystem advisories come from
      # deps.dev/OSV, which covers every system the lens serves.
      VulnerabilityHelper.merge_advisories(deps_dev: deps_dev, ruby_advisory_db: [])
    end

    # The repo project_id from the package's default version, used only when the
    # locked version's deps.dev record is missing or carries no link.
    def project_id_from(name, ecosystem, default)
      version = default&.dig(:version)
      return if version.nil?

      DepsDevClient.version_info(gem_name: name, version: version, system: ecosystem)&.dig(:project_id)
    end

    # archived + last-commit for a flat github.com/owner/repo project, or {} for
    # anything else. deps.dev indexes github.com and gitlab.com only, but gitlab
    # subgroups nest arbitrarily and ecosyste.ms's repo crawler is GitHub-centric,
    # so a gitlab (or nested, or unresolved) project keeps archived unknown rather
    # than risk a bogus owner/name lookup.
    def repo_signals(project_id)
      host, owner, name, *rest = project_id.to_s.split("/")
      return {} unless host == "github.com" && owner && name && rest.empty?

      repo_provider.repo_signals(owner: owner, name: name) || {}
    end

    # Mirrors Workflow#provider_for(:github): the live GitHub API when a token is
    # configured (freshest), else ecosyste.ms (5000 anonymous req/hr vs GitHub's
    # 60), so an untokened cross-ecosystem run still resolves a large SBOM.
    def repo_provider
      StillActive.config.github_oauth_token ? GithubClient : EcosystemsClient
    end
  end
end
