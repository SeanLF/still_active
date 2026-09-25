# frozen_string_literal: true

require_relative "errors"
require_relative "github_client"
require_relative "gitlab_client"
require_relative "forgejo_client"
require_relative "ecosystems_client"

module StillActive
  # One answer to "is this repository archived, and when was it last pushed?"
  # for both audit paths, from whichever service can give it. The clients only
  # report what their service said; which services to ask, in what order, and
  # when to stop, is decided here once.
  #
  # Returns a hash whose :check says what came of it, always one of:
  #   "answered"    a service said; :archived, :last_commit_date and :source
  #                 (which service) come with it
  #   "failed"      a service couldn't answer (a rate limit, an error, a refused
  #                 token) and none other said; a rerun may help, so the activity
  #                 gates fail closed on it
  #   "unknowable"  no service can say: the host has no archived state we can
  #                 read, there's no repository to ask about, or every service
  #                 asked didn't know it (ecosyste.ms hasn't crawled it, the forge
  #                 404s a private or deleted repository). A rerun won't change
  #                 it, so it reads unknown without failing the gates.
  #
  # "Don't know" is never an answer: a 404 or an answer without the archived
  # state moves on to the next service.
  #
  # A GitHub repository is asked of GitHub and of ecosyste.ms, which mirrors the
  # same two fields: GitHub first with a token (freshest, 5000/hr), ecosyste.ms
  # first without one (GitHub allows 60 anonymous requests an hour), each the
  # other's fallback. ecosyste.ms sees the repository's name, so it is asked only
  # when the dependency came from a public registry (`public:`), which is the
  # privacy guard; after GitHub refused the token outright (401/403: a bad token,
  # SSO, a suspended account) the chain also stops rather than guess.
  module RepositorySignals
    extend self

    # A service in a chain: its label for `source`, and how to ask it.
    Service = Data.define(:label, :ask)

    def for(host:, owner:, name:, public:)
      services = (host && owner && name) ? chain(host.downcase, public) : []
      return {check: "unknowable"} if services.empty?

      failed = false
      services.each do |service|
        signals = service.ask.call(owner, name)
        next unless signals.key?(:archived)

        return signals.merge(source: service.label, check: "answered")
      rescue RepoAccessDenied
        failed = true
        break
      rescue RepoSignalsUnavailable
        failed = true
      end

      if failed
        warn("warning: #{owner}/#{name}: no repository source could answer; archived status unknown")
        {check: "failed"}
      else
        {check: "unknowable"}
      end
    end

    # For a deps.dev project id (host/owner/name, host/group/.../name on
    # GitLab). gopkg.in is a redirector with a fixed mapping onto GitHub
    # (gopkg.in/pkg.v3 is github.com/go-pkg/pkg, gopkg.in/user/pkg.v3 is
    # github.com/user/pkg), so it is asked about as that GitHub repository.
    def for_project(project_id, public:)
      host, *path = project_id.to_s.split("/")
      host, path = gopkg_in(path) if host&.downcase == "gopkg.in"
      return {check: "unknowable"} if host.nil? || path.size < 2

      self.for(host: host, owner: path[0..-2].join("/"), name: path.last, public: public)
    end

    private

    GOPKG_VERSIONED = /\A(?<name>.+)\.v\d+(?:-unstable)?\z/

    def gopkg_in(path)
      match = path.last&.match(GOPKG_VERSIONED)
      return [nil, []] unless match

      owner = (path.size == 1) ? "go-#{match[:name]}" : path.first
      ["github.com", [owner, match[:name]]]
    end

    def chain(host, public)
      case host
      when "github.com" then github_chain(public)
      when "gitlab.com" then [Service.new("gitlab", ->(owner, name) { GitlabClient.repo_signals(owner: owner, name: name) })]
      when "codeberg.org" then [Service.new("codeberg", ->(owner, name) { ForgejoClient.repo_signals(owner: owner, name: name, host: host) })]
      else []
      end
    end

    def github_chain(public)
      github = Service.new("github", ->(owner, name) { GithubClient.repo_signals(owner: owner, name: name) })
      mirror = Service.new("ecosyste.ms", ->(owner, name) { EcosystemsClient.repo_signals(owner: owner, name: name) })
      return [github] unless public

      StillActive.config.github_oauth_token ? [github, mirror] : [mirror, github]
    end
  end
end
