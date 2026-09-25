# frozen_string_literal: true

require "tmpdir"

RSpec.describe(StillActive::HttpCache) do
  around do |example|
    Dir.mktmpdir do |dir|
      previous = ENV["XDG_CACHE_HOME"]
      ENV["XDG_CACHE_HOME"] = dir
      example.run
    ensure
      ENV["XDG_CACHE_HOME"] = previous
    end
  end

  before do
    StillActive.config.http_cache = true
    allow(described_class).to(receive(:ttl).and_call_original)
  end

  let(:deps_dev) { URI("https://api.deps.dev") }

  def json(body) = {status: 200, body: body.to_json, headers: {"Content-Type" => "application/json"}}

  it("answers a repeat request from disk") do
    stub = stub_request(:get, "https://api.deps.dev/v3alpha/advisories/GHSA-x").to_return(json({"title" => "t"}))

    2.times { expect(StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/GHSA-x")).to(eq("title" => "t")) }

    expect(stub).to(have_been_requested.once)
  end

  # The version record carries advisoryKeys: an hour at most, so a new CVE is at
  # most an hour late.
  it("keeps an advisory-bearing answer for an hour, not longer") do
    stub = stub_request(:get, %r{/versions/1\.0\.0\z}).to_return(json({"advisoryKeys" => []}))
    path = "/v3alpha/systems/npm/packages/x/versions/1.0.0"

    StillActive::HttpHelper.get_json(deps_dev, path)
    allow(Time).to(receive(:now).and_return(Time.now + 59 * 60))
    StillActive::HttpHelper.get_json(deps_dev, path)
    expect(stub).to(have_been_requested.once)

    allow(Time).to(receive(:now).and_return(Time.now + 61 * 60))
    StillActive::HttpHelper.get_json(deps_dev, path)
    expect(stub).to(have_been_requested.twice)
  end

  it("doesn't cache a failure or a 404, a credentialed request, an unlisted host, or with --no-cache") do
    stub_request(:get, "https://api.deps.dev/v3alpha/advisories/down").to_return(status: 503)
    stub_request(:get, "https://api.deps.dev/v3alpha/advisories/none").to_return(status: 404)
    stub_request(:get, "https://api.deps.dev/v3alpha/advisories/auth").to_return(json({}))
    stub_request(:get, "https://gitlab.com/api/v4/projects/x").to_return(json({}))
    stub_request(:get, "https://api.deps.dev/v3alpha/advisories/off").to_return(json({}))

    2.times do
      expect { StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/down") }.to(output.to_stderr)
      StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/none")
      StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/auth", headers: {"Authorization" => "Bearer t"})
      StillActive::HttpHelper.get_json(URI("https://gitlab.com"), "/api/v4/projects/x")
    end
    StillActive.config.http_cache = false
    2.times { StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/off") }

    %w[down none auth off].each { expect(a_request(:get, "https://api.deps.dev/v3alpha/advisories/#{_1}")).to(have_been_made.twice) }
    expect(a_request(:get, "https://gitlab.com/api/v4/projects/x")).to(have_been_made.twice)
  end

  it("reads a corrupt entry as a miss") do
    stub = stub_request(:get, "https://api.deps.dev/v3alpha/advisories/GHSA-x").to_return(json({"title" => "t"}))
    StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/GHSA-x")
    Dir.glob(File.join(described_class.directory, "*", "*.json")).each { File.write(_1, "{not json") }

    expect(StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/GHSA-x")).to(eq("title" => "t"))
    expect(stub).to(have_been_requested.twice)
  end

  it("serves a strict caller from the cache too") do
    stub = stub_request(:get, %r{/versions/1\.0\.0\z}).to_return(json({"advisoryKeys" => []}))
    path = "/v3alpha/systems/npm/packages/x/versions/1.0.0"

    2.times { expect(StillActive::HttpHelper.get_json(deps_dev, path, strict: true)).to(eq("advisoryKeys" => [])) }
    expect(stub).to(have_been_requested.once)
  end

  # OSV's version query is the arbiter that drops deps.dev findings, so it must
  # never be older than the record it judges: a cached query could drop an
  # advisory published after it was cached.
  it("never caches OSV's version query") do
    stub = stub_request(:post, "https://api.osv.dev/v1/query").to_return(json({}))

    2.times { StillActive::HttpHelper.post_json(URI("https://api.osv.dev"), "/v1/query", body: "{}") }

    expect(stub).to(have_been_requested.twice)
  end

  # The canaries check deps.dev as it is now; from the cache they'd check nothing.
  it("lets the canaries bypass the cache") do
    stub = stub_request(:get, %r{/packages/django/versions/3\.0\.0\z}).to_return(json({"advisoryKeys" => [{"id" => "A"}]}))
    package = stub_request(:get, %r{/packages/next\z}).to_return(json({"versions" => []}))

    2.times do
      StillActive::DepsDevClient.advisory_schema_ok?
      StillActive::DepsDevClient.newest_publish_date(name: "next", system: :npm)
    end

    expect(stub).to(have_been_requested.twice)
    expect(package).to(have_been_requested.twice)
  end

  # A version record is only cached once it has the shape we read, so the retry
  # after a garbled answer asks again rather than rereading it.
  it("doesn't cache a version record without advisoryKeys") do
    stub = stub_request(:get, %r{/versions/1\.0\.0\z}).to_return(json({"code" => 13})).then.to_return(json({"advisoryKeys" => []}))

    result = nil
    expect { result = StillActive::DepsDevClient.version_info(gem_name: "x", version: "1.0.0", system: :npm) }.to(output.to_stderr)

    expect(result[:advisory_keys]).to(eq([]))
    expect(stub).to(have_been_requested.twice)
  end

  it("reads an entry stamped in the future as a miss") do
    stub = stub_request(:get, "https://api.deps.dev/v3alpha/advisories/GHSA-x").to_return(json({"title" => "t"}))
    StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/GHSA-x")
    Dir.glob(File.join(described_class.directory, "*", "*.json")).each do |path|
      File.write(path, JSON.generate(JSON.parse(File.read(path)).merge("stored_at" => Time.now.to_f + 3600)))
    end

    StillActive::HttpHelper.get_json(deps_dev, "/v3alpha/advisories/GHSA-x")

    expect(stub).to(have_been_requested.twice)
  end
end
