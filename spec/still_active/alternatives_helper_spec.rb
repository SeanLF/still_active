# frozen_string_literal: true

require_relative "../../lib/still_active/helpers/alternatives_helper"

RSpec.describe(StillActive::AlternativesHelper) do
  describe(".leads_for") do
    let(:index) { {"cancan" => ["pundit", "cancancan", "rabarber"]} }

    before do
      allow(Gems).to(receive(:info).with("pundit").and_return({"downloads" => 102}))
      allow(Gems).to(receive(:info).with("cancancan").and_return({"downloads" => 90}))
      allow(Gems).to(receive(:info).with("rabarber").and_return({"downloads" => 1}))
    end

    it("returns the top 3 siblings ranked by downloads") do
      expect(described_class.leads_for(gem_name: "cancan", index: index))
        .to(eq(["pundit", "cancancan", "rabarber"]))
    end

    it("respects a custom limit") do
      expect(described_class.leads_for(gem_name: "cancan", index: index, limit: 1)).to(eq(["pundit"]))
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

    it("keeps zero-download siblings rather than dropping them") do
      allow(Gems).to(receive(:info).with("rabarber").and_return({"downloads" => 0}))
      expect(described_class.leads_for(gem_name: "cancan", index: index))
        .to(eq(["pundit", "cancancan", "rabarber"]))
    end

    it("looks up at most MAX_SIBLINGS_CONSIDERED siblings for a huge category") do
      big_category = (1..50).map { |i| "gem#{i}" }
      allow(Gems).to(receive(:info).and_return({"downloads" => 1}))
      described_class.leads_for(gem_name: "x", index: {"x" => big_category})
      expect(Gems).to(have_received(:info).at_most(described_class::MAX_SIBLINGS_CONSIDERED).times)
    end
  end
end
