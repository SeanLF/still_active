# frozen_string_literal: true

require_relative "../../lib/helpers/ansi_helper"

RSpec.describe(StillActive::AnsiHelper) do
  describe("colour methods") do
    it("wraps text in green escape codes") do
      expect(described_class.green("ok")).to(eq("\e[32mok\e[0m"))
    end

    it("wraps text in yellow escape codes") do
      expect(described_class.yellow("stale")).to(eq("\e[33mstale\e[0m"))
    end

    it("wraps text in red escape codes") do
      expect(described_class.red("critical")).to(eq("\e[31mcritical\e[0m"))
    end

    it("wraps text in dim escape codes") do
      expect(described_class.dim("-")).to(eq("\e[2m-\e[0m"))
    end

    it("wraps text in bold escape codes") do
      expect(described_class.bold("Name")).to(eq("\e[1mName\e[0m"))
    end
  end

  describe(".visible_length") do
    it("returns length of plain text") do
      expect(described_class.visible_length("hello")).to(eq(5))
    end

    it("strips ANSI codes before measuring") do
      coloured = described_class.green("ok")
      expect(described_class.visible_length(coloured)).to(eq(2))
    end

    it("handles text with multiple ANSI sequences") do
      text = "#{described_class.bold("a")} #{described_class.red("b")}"
      expect(described_class.visible_length(text)).to(eq(3))
    end
  end

  describe(".pad") do
    it("right-pads plain text to the given width") do
      expect(described_class.pad("hi", 5)).to(eq("hi   "))
    end

    it("right-pads coloured text accounting for invisible escape codes") do
      coloured = described_class.green("ok")
      padded = described_class.pad(coloured, 5)
      expect(described_class.visible_length(padded)).to(eq(5))
      expect(padded).to(end_with("   "))
    end

    it("does not truncate when text is wider than width") do
      expect(described_class.pad("hello", 3)).to(eq("hello"))
    end
  end
end
