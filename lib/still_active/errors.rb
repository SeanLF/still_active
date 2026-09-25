# frozen_string_literal: true

module StillActive
  class Error < StandardError; end
  class MissingLockfileError < Error; end

  # A repository provider couldn't answer (a rate limit, a timeout, an error
  # status, a garbled body), as opposed to answering that the repo isn't there.
  # The caller marks the repository unavailable rather than reading its blank
  # archived flag as "not archived".
  class RepoSignalsUnavailable < Error; end
end
