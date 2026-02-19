# frozen_string_literal: true

module StillActive
  module AnsiHelper
    extend self

    RESET = "\e[0m"
    ANSI_PATTERN = /\e\[[0-9;]*m/

    def green(text) = "\e[32m#{text}#{RESET}"
    def yellow(text) = "\e[33m#{text}#{RESET}"
    def red(text) = "\e[31m#{text}#{RESET}"
    def dim(text) = "\e[2m#{text}#{RESET}"
    def bold(text) = "\e[1m#{text}#{RESET}"

    def visible_length(text)
      text.gsub(ANSI_PATTERN, "").length
    end

    def pad(text, width)
      padding = width - visible_length(text)
      padding > 0 ? "#{text}#{" " * padding}" : text
    end
  end
end
