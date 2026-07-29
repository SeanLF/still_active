# frozen_string_literal: true

require_relative "../../lib/still_active/compact_index_client"

RSpec.describe(StillActive::CompactIndexClient) do
  before { StillActive.reset }

  let(:source_uri) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/" }
  let(:gem_name) { "sidekiq-pro" }
  let(:info_url) { "https://my-org.jfrog.io/artifactory/api/gems/my-repo/info/#{gem_name}" }
  # Trimmed from the real Artifactory /info/sidekiq-pro output on issue #142.
  let(:info_body) do
    <<~INFO
      ---
      0.0.3 |checksum:40c1
      8.1.4 sidekiq:< 9&>= 8.1.0|checksum:39f6,ruby:>= 3.2.0
      8.1.5 sidekiq:< 9&>= 8.1.0|checksum:e6b7,ruby:>= 3.2.0
    INFO
  end

  describe(".versions") do
    it("returns every version in the compact index, newest first") do
      stub_request(:get, info_url).to_return(status: 200, body: info_body)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["8.1.5", "8.1.4", "0.0.3"]))
    end

    it("flags pre-releases, so find_version can tell them from stable releases") do
      stub_request(:get, info_url).to_return(status: 200, body: "---\n1.0.0 |checksum:aa\n2.0.0.rc1 |checksum:bb\n")

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h.values_at("number", "prerelease") })
        .to(eq([["2.0.0.rc1", true], ["1.0.0", false]]))
    end

    it("carries the declared Ruby requirement, the language-ceiling input") do
      stub_request(:get, info_url).to_return(status: 200, body: info_body)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["ruby_version"] }).to(eq([">= 3.2.0", ">= 3.2.0", nil]))
    end

    it("collapses a version's per-platform rows into one entry") do
      # /info/ lists a row per built platform; the audit reasons about versions.
      body = "---\n1.0.0 |checksum:aa\n1.0.0-arm64-darwin |checksum:bb\n1.0.0-x86_64-linux |checksum:cc\n"
      stub_request(:get, info_url).to_return(status: 200, body: body)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["1.0.0"]))
    end

    it("skips the blank lines Artifactory is known to emit in index files") do
      stub_request(:get, info_url).to_return(status: 200, body: "---\n1.0.0 |checksum:aa\n\n2.0.0 |checksum:bb\n\n")

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["number"] }).to(eq(["2.0.0", "1.0.0"]))
    end

    it("reads the release date when the index supplies one") do
      # rubygems.org emits created_at in every /info/ row. Artifactory does not
      # (0 of 114 rows on issue #142), so this is best-effort, not a given.
      stub_request(:get, info_url)
        .to_return(status: 200, body: "---\n1.0.0 |checksum:aa,created_at:2026-06-18T15:18:58Z\n")

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.first["created_at"]).to(eq("2026-06-18T15:18:58Z"))
    end

    it("keeps the platform-independent row, which carries the full dependency set") do
      # /info/ lists platform variants before the generic row, and a native gem's
      # variants declare fewer dependencies than the ruby-platform build.
      body = "---\n1.0.0-aarch64-linux racc:~> 1.4|checksum:aa\n1.0.0 mini_portile2:~> 2.8,racc:~> 1.4|checksum:bb\n"
      stub_request(:get, info_url).to_return(status: 200, body: body)

      result = described_class.versions(gem_name: gem_name, source_uri: source_uri)

      expect(result.map { |h| h["checksum"] }).to(eq(["bb"]))
    end

    it("returns empty when the host does not serve a compact index") do
      stub_request(:get, info_url).to_return(status: 404)

      expect(described_class.versions(gem_name: gem_name, source_uri: source_uri)).to(eq([]))
    end

    it("warns rather than silently trusting a 200 that is not a compact index") do
      # A proxy/auth wall answering /info/ with an HTML 200 parses to no versions.
      # The compact index is now the primary source, so this must be loud: a silent
      # empty result would look identical to a clean parse and hide a broken source.
      stub_request(:get, info_url).to_return(status: 200, body: "<html><body>Login required</body></html>")

      expect { described_class.versions(gem_name: gem_name, source_uri: source_uri) }
        .to(output(/my-org\.jfrog\.io.*not a .*compact index/m).to_stderr)
    end

    it("stays quiet for an all-yanked gem whose index is just the header") do
      # A valid but empty compact index (every version yanked) is "---" with no
      # rows. That is not a broken source, so it must not warn.
      stub_request(:get, info_url).to_return(status: 200, body: "---\n")

      expect { described_class.versions(gem_name: gem_name, source_uri: source_uri) }
        .not_to(output.to_stderr)
    end
  end

  # Canary. CompactIndexClient#metadata hand-parses the compact-index requirements
  # instead of using Gem::Resolver::APISet::GemParser, because GemParser mangles a
  # colon-bearing created_at (the compact index v2 field) until the first-colon fix
  # in rubygems 4.0.13. That fix is 4.0-only; the 3.5.x/3.6.x lines our Rubies ship
  # are dormant (last releases 2024/2025, predating it), so the realistic trigger
  # for retiring the workaround is raising required_ruby_version to a Ruby bundling
  # >= 4.0.13, not a backport. So key the canary off the FLOOR Ruby: it fires on
  # that job whether the fix arrives by backport or by a raised floor, and stays
  # quiet on the higher matrix jobs (which already have the fix and can't act for
  # the floor).
  it "canary: retire the compact-index metadata hand-parse once the floor Ruby ships a fixed rubygems" do
    gemspec = Gem::Specification.load(File.expand_path("../../still_active.gemspec", __dir__))
    floor = gemspec.required_ruby_version.requirements.find { |operator, _| operator == ">=" }&.last
    on_floor_ruby = floor && Gem::Version.new(RUBY_VERSION).segments.first(2) == floor.segments.first(2)
    skip "only meaningful on the minimum supported Ruby (#{floor})" unless on_floor_ruby

    expect(Gem::Version.new(Gem::VERSION)).to(be < Gem::Version.new("4.0.13"),
      "the floor Ruby #{RUBY_VERSION} now ships rubygems #{Gem::VERSION} (>= 4.0.13) -- replace " \
      "CompactIndexClient#metadata with GemParser + to_h and delete this canary")
  end
end
