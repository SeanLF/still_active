# frozen_string_literal: true

require_relative "../assessment"

module StillActive
  # Reading a dependency's repository_check the same way everywhere: "answered",
  # "failed" or "unknowable" (see RepositorySignals), or "not_applicable" for the
  # Go toolchain, which is the language, not a package with a repository. A hash
  # without the key never had its repository looked at, which is not an answer.
  module RepositoryCheck
    extend self

    VALUES = Assessment::REPOSITORY_CHECKS
    SETTLED = ["answered", "not_applicable"].freeze

    def unanswered?(data) = !SETTLED.include?(data[:repository_check])

    # A missing or unrecognised check means the repository step never ran (an
    # assessment that raised part-way), so it counts as failed, as in tally.
    def failed?(data) = !VALUES.include?(data[:repository_check]) || data[:repository_check] == "failed"

    # {answered:, failed:, unknowable:} across dependencies.
    def tally(dependencies)
      counts = VALUES.to_h { [_1.to_sym, 0] }
      dependencies.each { counts[(data_check(_1) || "failed").to_sym] += 1 }
      counts
    end

    private

    def data_check(data) = VALUES.include?(data[:repository_check]) ? data[:repository_check] : nil
  end
end
