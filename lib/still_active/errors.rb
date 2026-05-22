# frozen_string_literal: true

module StillActive
  class Error < StandardError; end
  class MissingLockfileError < Error; end
end
