# frozen_string_literal: true

module StillActive
  # Escaping for untrusted metadata (gem names, licences, versions, repo URLs,
  # advisory ids) rendered into GitHub-Flavored Markdown. These values come
  # from registry/repo metadata, a Gemfile/lockfile, a --baseline file, or
  # --gems input, so they can contain markdown-structural characters. Centralised
  # so the table renderer (MarkdownHelper) and the diff renderer
  # (DiffMarkdownHelper) can't drift apart on what's safe.
  module MarkdownEscape
    extend self

    # Table cell: a literal "|" or newline would forge columns or break the row.
    # Backslash is escaped first so it can't escape a following delimiter.
    def cell(text)
      return text if text.nil?

      text.to_s.gsub(/[\\|\r\n]/, "\\" => "\\\\", "|" => "\\|", "\r" => " ", "\n" => " ")
    end

    # Link text additionally must not contain "[" or "]", which could forge or
    # truncate the link.
    def link_text(text)
      return text if text.nil?

      cell(text).gsub(/[\[\]]/, "[" => "\\[", "]" => "\\]")
    end

    # Link destination: percent-encode the characters that would break out of a
    # "(...)" destination or the table row. Lossless for legitimate http(s) URLs.
    def url(value)
      return value if value.nil?

      value.to_s.gsub(/[|() \t\r\n]/, "|" => "%7C", "(" => "%28", ")" => "%29", " " => "%20", "\t" => "%09", "\r" => "%0D", "\n" => "%0A")
    end

    # Inline (non-table) free text in a bullet list: neutralise newlines (which
    # would break the list) and brackets/backslash (which could forge a link).
    def inline(text)
      return text if text.nil?

      text.to_s.gsub(/[\\\[\]\r\n]/, "\\" => "\\\\", "[" => "\\[", "]" => "\\]", "\r" => " ", "\n" => " ")
    end

    # Wrap arbitrary text in an inline code span safely. A backtick in the text
    # would otherwise close the span early, so use a backtick fence longer than
    # the longest run in the content (and pad when it starts/ends with one), per
    # the GFM code-span rules. Newlines collapse to spaces.
    def code_span(text)
      content = text.to_s.tr("\r\n", "  ")
      return "`#{content}`" unless content.include?("`")

      fence = "`" * (content.scan(/`+/).map(&:length).max + 1)
      pad = content.start_with?("`") || content.end_with?("`") ? " " : ""
      "#{fence}#{pad}#{content}#{pad}#{fence}"
    end
  end
end
