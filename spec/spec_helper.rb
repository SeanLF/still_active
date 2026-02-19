# frozen_string_literal: true

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

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with(:rspec) do |c|
    c.syntax = :expect
  end
end
