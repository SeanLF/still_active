# frozen_string_literal: true

require_relative "../../lib/helpers/markdown_escape"

RSpec.describe(StillActive::MarkdownEscape) do
  describe(".cell") do
    it("escapes pipes, backslashes, and newlines") do
      expect(described_class.cell("a|b")).to(eq("a\\|b"))
      expect(described_class.cell("a\\b")).to(eq("a\\\\b"))
      expect(described_class.cell("a\nb")).to(eq("a b"))
    end

    it("escapes the backslash before the pipe it precedes") do
      expect(described_class.cell("a\\|b")).to(eq("a\\\\\\|b"))
    end

    it("passes nil through") do
      expect(described_class.cell(nil)).to(be_nil)
    end
  end

  describe(".link_text") do
    it("escapes brackets in addition to cell characters") do
      expect(described_class.link_text("[x]")).to(eq("\\[x\\]"))
    end
  end

  describe(".url") do
    it("percent-encodes characters that would break the destination or row") do
      expect(described_class.url("https://h/a b|c(d)")).to(eq("https://h/a%20b%7Cc%28d%29"))
    end

    it("leaves a normal http(s) URL untouched") do
      expect(described_class.url("https://github.com/rails/rails")).to(eq("https://github.com/rails/rails"))
    end
  end

  describe(".inline") do
    it("neutralises newlines and brackets but leaves pipes (not a table)") do
      expect(described_class.inline("a\n- x [y]")).to(eq("a - x \\[y\\]"))
      expect(described_class.inline("a|b")).to(eq("a|b"))
    end
  end

  describe(".code_span") do
    it("wraps plain text in single backticks") do
      expect(described_class.code_span("rails")).to(eq("`rails`"))
    end

    it("uses a longer fence than the longest internal backtick run") do
      expect(described_class.code_span("a`b")).to(eq("``a`b``"))
      expect(described_class.code_span("a``b")).to(eq("```a``b```"))
    end

    it("pads when the content starts or ends with a backtick") do
      expect(described_class.code_span("`x")).to(eq("`` `x ``"))
    end

    it("collapses newlines so the span stays on one line") do
      expect(described_class.code_span("a\nb")).to(eq("`a b`"))
    end
  end
end
