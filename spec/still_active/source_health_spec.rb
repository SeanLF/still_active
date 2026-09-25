# frozen_string_literal: true

RSpec.describe(StillActive::SourceHealth) do
  let(:now) { Time.utc(2026, 9, 24) }

  before do
    allow(described_class).to(receive(:check).and_call_original)
    allow(StillActive::DepsDevClient).to(receive_messages(advisory_schema_ok?: true, newest_publish_date: nil))
  end

  def published(name, date)
    allow(StillActive::DepsDevClient).to(receive(:newest_publish_date).with(name: name, system: anything).and_return(date))
  end

  it("is healthy when the advisory canary answers and each ecosystem's index is current") do
    published("next", "2026-09-19T00:00:00Z")
    published("boto3", "2026-09-24T00:00:00Z")

    report = described_class.check(ecosystems: [:npm, :pypi, :npm], now: now)

    expect(report).not_to(be_degraded)
    expect(report.deps_dev_trusted?(:npm)).to(be(true))
    expect(report.as_json).to(eq(status: "ok", deps_dev_advisories: "ok", deps_dev_stale_ecosystems: []))
  end

  # One quiet canary isn't a stalled index; every one of them quiet is.
  it("reads an ecosystem fresh when any one of its canaries published in the window") do
    published("aws-sdk-ec2", "2026-06-01T00:00:00Z")
    published("oxc_parser", nil)
    published("swc_core", "2026-09-20T00:00:00Z")

    expect(described_class.check(ecosystems: [:cargo], now: now).stale_ecosystems).to(be_empty)
  end

  it("distrusts an ecosystem none of whose canaries published in 30 days, or could be read") do
    published("next", "2026-07-01T00:00:00Z")
    published("@types/node", "2026-07-02T00:00:00Z")
    published("aws-sdk-ec2", "2026-09-20T00:00:00Z")

    report = described_class.check(ecosystems: [:npm, :pypi, :cargo], now: now)

    expect(report.stale_ecosystems).to(eq([:npm, :pypi]))
    expect(report.deps_dev_trusted?(:cargo)).to(be(true))
    expect(report.warnings.join).to(include("npm index", "pypi index", "unless another source answers"))
  end

  it("doesn't count a canary deps.dev couldn't answer for") do
    allow(StillActive::DepsDevClient).to(receive(:newest_publish_date).with(name: "next", system: :npm).and_raise(StillActive::HttpHelper::Unavailable))
    published("@types/node", "2026-09-20T00:00:00Z")

    expect(described_class.check(ecosystems: [:npm], now: now).stale_ecosystems).to(be_empty)
  end

  it("distrusts every ecosystem when the advisory canary fails") do
    allow(StillActive::DepsDevClient).to(receive(:advisory_schema_ok?).and_return(false))
    published("next", "2026-09-19T00:00:00Z")

    report = described_class.check(ecosystems: [:npm], now: now)

    expect(report.deps_dev_trusted?(:npm)).to(be(false))
    expect(report.as_json).to(include(status: "degraded", deps_dev_advisories: "failed"))
  end

  it("skips an ecosystem it has no canary for rather than calling it stale") do
    expect(described_class.check(ecosystems: [:hex], now: now).stale_ecosystems).to(be_empty)
  end

  it("reads a garbled date as not fresh") do
    published("next", "not a date")
    published("@types/node", nil)

    expect(described_class.check(ecosystems: [:npm], now: now).stale_ecosystems).to(eq([:npm]))
  end
end
