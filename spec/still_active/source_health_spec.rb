# frozen_string_literal: true

RSpec.describe(StillActive::SourceHealth) do
  let(:now) { Time.utc(2026, 9, 24) }

  before do
    allow(described_class).to(receive(:check).and_call_original)
    allow(StillActive::DepsDevClient).to(receive(:advisory_schema_ok?).and_return(true))
  end

  def released(ecosystem, date)
    allow(StillActive::DepsDevClient).to(receive(:latest_release_date)
      .with(name: described_class::FRESHNESS_CANARIES[ecosystem], system: ecosystem).and_return(date))
  end

  it("is healthy when the advisory canary answers and each ecosystem's index is current") do
    released(:npm, "2026-09-19T00:00:00Z")
    released(:pypi, "2026-09-24T00:00:00Z")

    report = described_class.check(ecosystems: [:npm, :pypi, :npm], now: now)

    expect(report).not_to(be_degraded)
    expect(report.deps_dev_trusted?(:npm)).to(be(true))
    expect(report.as_json).to(eq(status: "ok", deps_dev_advisories: "ok", deps_dev_stale_ecosystems: []))
  end

  it("distrusts an ecosystem whose canary hasn't released in 30 days, or can't be read") do
    released(:npm, "2026-07-01T00:00:00Z")
    released(:pypi, nil)
    released(:cargo, "2026-09-20T00:00:00Z")

    report = described_class.check(ecosystems: [:npm, :pypi, :cargo], now: now)

    expect(report.stale_ecosystems).to(eq([:npm, :pypi]))
    expect(report.deps_dev_trusted?(:cargo)).to(be(true))
    expect(report.deps_dev_trusted?(:npm)).to(be(false))
    expect(report.warnings.join).to(include("npm index", "pypi index"))
  end

  it("distrusts every ecosystem when the advisory canary fails") do
    allow(StillActive::DepsDevClient).to(receive(:advisory_schema_ok?).and_return(false))
    released(:npm, "2026-09-19T00:00:00Z")

    report = described_class.check(ecosystems: [:npm], now: now)

    expect(report.deps_dev_trusted?(:npm)).to(be(false))
    expect(report.as_json).to(include(status: "degraded", deps_dev_advisories: "failed"))
  end

  it("skips an ecosystem it has no canary for rather than calling it stale") do
    report = described_class.check(ecosystems: [:hex], now: now)

    expect(report.stale_ecosystems).to(be_empty)
  end

  it("reads a garbled date as not fresh") do
    released(:npm, "not a date")

    expect(described_class.check(ecosystems: [:npm], now: now).stale_ecosystems).to(eq([:npm]))
  end
end
