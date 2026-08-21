# frozen_string_literal: true

require_relative "endoflife_helper"

module StillActive
  # Python's calibration for the language-runtime ceiling: the thin sibling of
  # RubyHelper.supported_ruby_range. Python declares its runtime constraint as a
  # PEP 440 `requires_python` specifier (translate with Pep440Helper before
  # handing it to RuntimeCeilingHelper), and its release calendar lives in the
  # same endoflife.date feed. Everything ecosystem-neutral is in EndoflifeHelper;
  # Python only chooses the feed path.
  module PythonHelper
    extend self

    def supported_python_range
      EndoflifeHelper.support_window(feed_path: "/api/python.json")
    end
  end
end
