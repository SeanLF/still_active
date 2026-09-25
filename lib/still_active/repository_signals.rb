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
  # Returns one of:
  #   {archived:, last_commit_date:, source:}  a service answered; source names it
  #   {}                                       nothing to ask about (no repository,
  #                                            or a host no service covers)
  #   {unavailable: true}                      no service could say, so archived is
  #                                            unknown, not false
  #
  # "Don't know" is never an answer: ecosyste.ms's 404 for a repository it hasn't
  # crawled, an answer without the archived state, and a forge's own 404 all move
  # on to the next service. A forge 404s a private repository to anyone who can't
  # see it (every anonymous request), so its 404 can't tell "doesn't exist" from
  # "can't see"; and a repository that really is gone isn't healthy either.
  #
  # A GitHub repository is asked of GitHub and of ecosyste.ms, which mirrors the
  # same two fields: GitHub first with a token (freshest, 5000/hr), ecosyste.ms
  # first without one (GitHub allows 60 anonymous requests an hour), each the
  # other's fallback. ecosyste.ms sees the repository's name, so it is asked only
  # when the dependency came from a public registry (`public:`), and never after
  # GitHub refused the token (401/403), which suggests a private repository.
  module RepositorySignals
    extend self

    # A service in a chain: its label for `source`, and how to ask it.
    Service = Data.define(:label, :ask)

    def for(host:, owner:, name:, public:)
      return {} if host.nil? || owner.nil? || name.nil?

      services = chain(host.downcase, public)
      return {} if services.empty?

      services.each do |service|
        signals = service.ask.call(owner, name)
        next unless signals.key?(:archived)

        return signals.merge(source: service.label)
      rescue RepoAccessDenied
        break
      rescue RepoSignalsUnavailable
        next
      end

      warn("warning: #{owner}/#{name}: no repository source answered; archived status unknown")
      {unavailable: true}
    end

    private

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
