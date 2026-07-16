# frozen_string_literal: true

require "json"
require "open3"

module StillActive
  # Best-effort detection of a Dependabot/Renovate-authored run, so --baseline
  # reports can lead with a narrative ("Dependabot bump: rack 2.0.0 → 2.0.6")
  # instead of an unattributed list. Detection is heuristic: false negatives are
  # fine (we just lose the narrative), false positives are not, so the subject
  # patterns are anchored and require the literal bump/update keyword.
  module BotContext
    extend self

    # Dependabot's *default* subject is "Bump X from Y to Z" (capitalized, no
    # prefix). The `from … to …` skeleton rarely occurs in human commits, so it
    # is safe unprefixed. The conventional-commit prefix only appears when configured.
    DEPENDABOT_SUBJECT = /\A(?:build\(deps(?:-dev)?\):\s*)?bump (\S+) from (\S+) to (\S+)/i

    # Renovate's default is "Update dependency X to vN.…" — note the **required**
    # `v`+digit version. Matching a bare "to <word>" would false-positive on ordinary
    # commits ("Update README to mention SARIF"), so we anchor on the v-prefixed
    # version. False negatives (a no-`v` Renovate config) are acceptable; false
    # positives are not. The `v` is consumed, so the captured version excludes it.
    RENOVATE_SUBJECT = /\A(?:(?:chore|fix|build)\(deps(?:-dev)?\):\s*)?update (?:dependency )?(\S+) to v(\d[\w.-]*)/i

    # Unanchored variants used only to EXTRACT the bump *after* a bot is already
    # confirmed (via GITHUB_ACTOR / branch / the anchored subject above). Because
    # detection has already happened, these can ignore whatever commit-message
    # prefix or scope Dependabot/Renovate is configured with and just find the
    # "bump X from Y to Z" / "update X to vN" skeleton anywhere in the subject.
    DEPENDABOT_BUMP = /bump (\S+) from (\S+) to (\S+)/i
    RENOVATE_BUMP = /update (?:dependency )?(\S+) to v(\d[\w.-]*)/i

    # Returns { bot: "dependabot" | "renovate", bumps: [{ gem:, from:, to: }] }
    # or nil when no bot signal is present. `bumps` is parsed from the head
    # commit subject; a grouped or unparseable subject yields an empty list.
    def detect(env: ENV, head_subject: head_commit_subject)
      bot = detect_bot(env: env, head_subject: head_subject)
      return if bot.nil?

      {bot: bot, bumps: bumps_from(bot, head_subject)}
    end

    # A one-line, format-agnostic narrative for the detected context.
    def summary(context)
      label = (context[:bot] == "renovate") ? "Renovate" : "Dependabot"
      bumps = context[:bumps]

      case bumps.length
      when 0 then "#{label} dependency update"
      when 1 then single_bump_summary(label, bumps.first)
      else "#{label}: #{bumps.length} dependency updates"
      end
    end

    private

    def detect_bot(env:, head_subject:)
      # The PR author from the event payload is the authoritative signal — it's
      # what `dependabot/fetch-metadata` keys on, and unlike GITHUB_ACTOR it
      # doesn't flip to a human who re-runs the workflow or pushes to the branch.
      login = pr_author_login(env)
      return "dependabot" if login == "dependabot[bot]"
      return "renovate" if login == "renovate[bot]"

      actor = env["GITHUB_ACTOR"]
      return "dependabot" if actor == "dependabot[bot]"
      return "renovate" if actor == "renovate[bot]"

      ref = env["GITHUB_HEAD_REF"] || current_branch
      return "dependabot" if ref&.start_with?("dependabot/")
      return "renovate" if ref&.start_with?("renovate/", "renovate-bot/")

      return "dependabot" if head_subject&.match?(DEPENDABOT_SUBJECT)
      return "renovate" if head_subject&.match?(RENOVATE_SUBJECT)

      nil
    end

    # Reads pull_request.user.login from the GitHub Actions event payload
    # (GITHUB_EVENT_PATH). Returns nil off Actions, on non-PR events, or if the
    # file is missing/unreadable/malformed — all of which just fall through to
    # the weaker signals. TypeError covers a payload that parses but has the
    # wrong shape (e.g. a top-level array, or pull_request/user not a Hash);
    # this method must never raise, since detect runs unguarded and a cosmetic
    # narrative must not be able to abort the audit.
    def pr_author_login(env)
      path = env["GITHUB_EVENT_PATH"]
      return if path.nil? || !File.file?(path)

      JSON.parse(File.read(path)).dig("pull_request", "user", "login")
    rescue JSON::ParserError, SystemCallError, TypeError
      nil
    end

    def bumps_from(bot, subject)
      return [] if subject.nil?

      if bot == "dependabot" && (match = subject.match(DEPENDABOT_BUMP))
        [{gem: match[1], from: match[2], to: match[3]}]
      elsif bot == "renovate" && (match = subject.match(RENOVATE_BUMP))
        [{gem: match[1], from: nil, to: match[2]}]
      else
        []
      end
    end

    def single_bump_summary(label, bump)
      arrow = bump[:from] ? "#{bump[:from]} → #{bump[:to]}" : "→ #{bump[:to]}"
      verb = (label == "Renovate") ? "update" : "bump"
      "#{label} #{verb}: #{bump[:gem]} #{arrow}"
    end

    # SystemCallError (not just Errno::ENOENT) so a git that's missing *or*
    # unlaunchable can't crash a run over a cosmetic narrative. git *logic*
    # failures surface as a non-zero status, not an exception, and yield nil.
    def current_branch
      out, _, status = Open3.capture3("git", "rev-parse", "--abbrev-ref", "HEAD")
      status.success? ? out.strip : nil
    rescue SystemCallError
      nil
    end

    def head_commit_subject
      out, _, status = Open3.capture3("git", "log", "-1", "--pretty=%s")
      status.success? ? out.strip : nil
    rescue SystemCallError
      nil
    end
  end
end
