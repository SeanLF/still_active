# frozen_string_literal: true

require_relative "../../lib/helpers/alternatives_helper"

RSpec.describe(StillActive::AlternativesHelper) do
  describe(".leads_for") do
    let(:index) { { "cancan" => ["pundit", "cancancan", "rabarber", "with/slug"] } }

    before do
      allow(Gems).to(receive(:info).with("pundit").and_return({ "downloads" => 102 }))
      allow(Gems).to(receive(:info).with("cancancan").and_return({ "downloads" => 90 }))
      allow(Gems).to(receive(:info).with("rabarber").and_return({ "downloads" => 1 }))
    end

    it("returns the top 3 siblings by downloads, slug entries dropped") do
      expect(described_class.leads_for(gem_name: "cancan", index: index))
        .to(eq(["pundit", "cancancan", "rabarber"]))
    end

    it("returns [] when the gem has no catalog entry") do
      expect(described_class.leads_for(gem_name: "unknown", index: index)).to(eq([]))
    end

    it("returns [] when the index is nil") do
      expect(described_class.leads_for(gem_name: "cancan", index: nil)).to(eq([]))
    end

    it("drops siblings whose download lookup fails, rather than the whole list") do
      allow(Gems).to(receive(:info).with("cancancan").and_raise(StandardError))
      expect(described_class.leads_for(gem_name: "cancan", index: index))
        .to(eq(["pundit", "rabarber"]))
    end
  end
end
