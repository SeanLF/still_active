# frozen_string_literal: true

module StillActive
  module CoreExt
    SECONDS_PER_YEAR = 31_556_952 # Gregorian average (365.2425 days)

    refine Numeric do
      def days = self * 86_400
      def years = self * SECONDS_PER_YEAR
      def ago = Time.now - self
    end
  end
end
