# frozen_string_literal: true

# Coverage is opt-in (COVERAGE=1) so a normal local run isn't slowed; CI sets it.
# Must start before still_active loads so every file is instrumented. The floor is a
# regression ratchet (fail if coverage drops), not a target to chase.
if ENV["COVERAGE"] == "1"
  require "simplecov"
  SimpleCov.start do
    add_filter "/spec/"
    enable_coverage :branch
    # Measured 96.3% line / 87.3% branch; floor sits a few points below as a
    # regression ratchet, loose enough not to flake on a legitimate change.
    minimum_coverage line: 92, branch: 82
  end
end

require "still_active"
require "vcr"
require "webmock/rspec"

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into(:webmock)
  config.filter_sensitive_data("<GITHUB_TOKEN>") { ENV.fetch("GITHUB_TOKEN", "") }
  config.filter_sensitive_data("<GITLAB_TOKEN>") { ENV.fetch("GITLAB_TOKEN", "") }
  config.filter_sensitive_data("<RUBYGEMS_API_KEY>") { ENV.fetch("RUBYGEMS_API_KEY", "") }
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Hermetic token resolution: neutralise the host's GitHub/GitLab CLI auth and
  # ambient token env vars by default, so the suite behaves identically on a dev
  # machine (which may have `gh`/`glab` logged in) and in CI (which doesn't). A
  # GitHub token quietly present locally otherwise masks token-dependent
  # failures -- e.g. the ecosyste.ms fallback only engages without a token --
  # until they surface in CI. Specs that need a token set it explicitly;
  # config_spec overrides these to exercise the real discovery cascade. Only the
  # gh/glab auth shell-outs are stubbed (git calls in BotContext pass through).
  config.before do
    # StillActive.config is a process-wide singleton that specs mutate (activity
    # ranges, ignored_gems, suppressions, tokens). Reset it before every example so
    # a mutation can't leak across files and make a later spec order-dependent
    # (e.g. a widened warning_range_end silently demoting an "abandoned" SARIF gem).
    # Runs before any describe-level `before`, so per-example config setup still wins.
    StillActive.reset

    ["GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN"].each { |var| ENV.delete(var) }
    allow(Open3).to(receive(:capture3).and_call_original)
    allow(Open3).to(receive(:capture3).with("gh", "auth", "token").and_raise(Errno::ENOENT))
    allow(Open3).to(receive(:capture3).with("glab", "auth", "status", "--hostname=gitlab.com", "--show-token").and_raise(Errno::ENOENT))

    # OSV advisory enrichment (OsvClient) fires on every advisory-bearing gem. Default
    # it to "no record" so specs that aren't about OSV stay hermetic without each
    # stubbing it; specs that exercise enrichment register a more specific stub_request
    # (or explicit response), which WebMock matches ahead of this catch-all.
    stub_request(:get, %r{api\.osv\.dev/v1/vulns/}).to_return(status: 404)
  end
end
