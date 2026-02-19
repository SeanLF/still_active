# `still_active`

Analyses your Gemfile dependencies for staleness: latest releases, last commit dates (GitHub and GitLab), OpenSSF Scorecard scores, and known vulnerabilities via deps.dev. Outputs coloured terminal tables, markdown, or JSON with CI gating support.

[![Gem Version](https://badge.fury.io/rb/still_active.svg)](https://badge.fury.io/rb/still_active)

![Code Quality analysis](https://github.com/SeanLF/still_active/actions/workflows/codeql-analysis.yml/badge.svg)
![RSpec](https://github.com/SeanLF/still_active/actions/workflows/rspec.yml/badge.svg)
![Rubocop analysis](https://github.com/SeanLF/still_active/actions/workflows/rubocop-analysis.yml/badge.svg)

## Installation

```bash
gem install still_active
```

## Usage

Tokens are read from `GITHUB_TOKEN` and `GITLAB_TOKEN` environment variables by default. Without a GitHub token you will most certainly get rate limited. The GitLab token is optional for public repos but required for private ones. CLI flags override the env vars.

```text
Usage: still_active [options]

        all flags are optional

        --gemfile=GEMFILE            path to gemfile
        --gems=GEM,GEM2,...          Gem(s)
        --terminal                   Coloured terminal output (default in TTY)
        --markdown                   Markdown table output
        --json                       JSON output (default when piped)
        --github-oauth-token=TOKEN   GitHub OAuth token to make API calls
        --gitlab-token=TOKEN         GitLab personal access token for API calls
        --simultaneous-requests=QTY  Number of simultaneous requests made
        --safe-range-end=YEARS       maximum years since last activity considered safe (no warning)
        --warning-range-end=YEARS    maximum years since last activity that triggers a warning (beyond this is critical)
        --fail-if-critical           Exit 1 if any gem has critical activity warning
        --fail-if-warning            Exit 1 if any gem has warning or critical activity warning
        --critical-warning-emoji=EMOJI
        --futurist-emoji=EMOJI
        --success-emoji=EMOJI
        --unsure-emoji=EMOJI
        --warning-emoji=EMOJI
    -h, --help                       Show this message
    -v, --version                    Show version
```

### Examples

```bash
still_active --json --gems=rails,nokogiri
```

Will output:

```json
{
  "rails": {
    "latest_version": "8.1.2",
    "latest_version_release_date": "2026-01-08 20:18:51 UTC",
    "latest_pre_release_version": "8.1.0.rc1",
    "latest_pre_release_version_release_date": "2025-10-15 00:52:14 UTC",
    "repository_url": "https://github.com/rails/rails",
    "last_commit_date": "2026-02-19 09:39:03 UTC",
    "scorecard_score": 5.7,
    "vulnerability_count": 0,
    "ruby_gems_url": "https://rubygems.org/gems/rails"
  },
  "nokogiri": {
    "latest_version": "1.19.1",
    "latest_version_release_date": "2026-02-16 23:31:21 UTC",
    "latest_pre_release_version": "1.18.0.rc1",
    "latest_pre_release_version_release_date": "2024-12-16 17:48:44 UTC",
    "repository_url": "https://github.com/sparklemotion/nokogiri",
    "last_commit_date": "2026-02-17 19:13:22 UTC",
    "scorecard_score": 6.5,
    "vulnerability_count": 0,
    "ruby_gems_url": "https://rubygems.org/gems/nokogiri"
  }
}
```

```bash
# run against this gem's own Gemfile
still_active --markdown
```

Outputs:

| activity | up to date? | OpenSSF | vulns | name                                                                       | version used                                                                      | latest version                                                                    | latest pre-release                                                                | last commit                                                  |
| -------- | ----------- | ------- | ----- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| ⚠️       | ✅          | 3.1/10  | ✅    | [code-scanning-rubocop](https://github.com/arthurnn/code-scanning-rubocop) | [0.6.1](https://rubygems.org/gems/code-scanning-rubocop/versions/0.6.1) (2022/02) | [0.6.1](https://rubygems.org/gems/code-scanning-rubocop/versions/0.6.1) (2022/02) | ❓                                                                                | [2024/06](https://github.com/arthurnn/code-scanning-rubocop) |
|          | ✅          | 5.2/10  | ✅    | [debug](https://github.com/ruby/debug)                                     | [1.11.1](https://rubygems.org/gems/debug/versions/1.11.1) (2025/12)               | [1.11.1](https://rubygems.org/gems/debug/versions/1.11.1) (2025/12)               | [1.0.0.rc2](https://rubygems.org/gems/debug/versions/1.0.0.rc2) (2021/09)         | [2025/12](https://github.com/ruby/debug)                     |
|          | ✅          | 7.4/10  | ✅    | [faker](https://github.com/faker-ruby/faker)                               | [3.6.0](https://rubygems.org/gems/faker/versions/3.6.0) (2026/01)                 | [3.6.0](https://rubygems.org/gems/faker/versions/3.6.0) (2026/01)                 | ❓                                                                                | [2026/02](https://github.com/faker-ruby/faker)               |
|          | ✅          | 5.3/10  | ✅    | [rake](https://github.com/ruby/rake)                                       | [13.3.1](https://rubygems.org/gems/rake/versions/13.3.1) (2025/10)                | [13.3.1](https://rubygems.org/gems/rake/versions/13.3.1) (2025/10)                | [13.0.0.pre.1](https://rubygems.org/gems/rake/versions/13.0.0.pre.1) (2019/09)    | [2026/02](https://github.com/ruby/rake)                      |
|          | ✅          | 6.9/10  | ✅    | [rspec](https://github.com/rspec/rspec)                                    | [3.13.2](https://rubygems.org/gems/rspec/versions/3.13.2) (2025/10)               | [3.13.2](https://rubygems.org/gems/rspec/versions/3.13.2) (2025/10)               | [4.0.0.beta1](https://rubygems.org/gems/rspec/versions/4.0.0.beta1) (2026/02)     | [2026/02](https://github.com/rspec/rspec)                    |
|          | ✅          | 5.9/10  | ✅    | [rubocop](https://github.com/rubocop/rubocop)                              | [1.84.2](https://rubygems.org/gems/rubocop/versions/1.84.2) (2026/02)             | [1.84.2](https://rubygems.org/gems/rubocop/versions/1.84.2) (2026/02)             | ❓                                                                                | [2026/02](https://github.com/rubocop/rubocop)                |
|          | ✅          | ❓      | ✅    | [rubocop-performance](https://github.com/rubocop/rubocop-performance)      | [1.26.1](https://rubygems.org/gems/rubocop-performance/versions/1.26.1) (2025/10) | [1.26.1](https://rubygems.org/gems/rubocop-performance/versions/1.26.1) (2025/10) | ❓                                                                                | [2026/01](https://github.com/rubocop/rubocop-performance)    |
|          | ✅          | ❓      | ✅    | [rubocop-rspec](https://github.com/rubocop/rubocop-rspec)                  | [3.9.0](https://rubygems.org/gems/rubocop-rspec/versions/3.9.0) (2026/01)         | [3.9.0](https://rubygems.org/gems/rubocop-rspec/versions/3.9.0) (2026/01)         | [3.0.0.pre](https://rubygems.org/gems/rubocop-rspec/versions/3.0.0.pre) (2024/06) | [2026/02](https://github.com/rubocop/rubocop-rspec)          |
|          | ✅          | ❓      | ✅    | [rubocop-shopify](https://github.com/Shopify/ruby-style-guide)             | [2.18.0](https://rubygems.org/gems/rubocop-shopify/versions/2.18.0) (2025/10)     | [2.18.0](https://rubygems.org/gems/rubocop-shopify/versions/2.18.0) (2025/10)     | ❓                                                                                | [2026/01](https://github.com/Shopify/ruby-style-guide)       |
|          | ✅          | ❓      | ✅    | [vcr](https://github.com/vcr/vcr)                                          | [6.4.0](https://rubygems.org/gems/vcr/versions/6.4.0) (2025/12)                   | [6.4.0](https://rubygems.org/gems/vcr/versions/6.4.0) (2025/12)                   | [2.0.0.rc2](https://rubygems.org/gems/vcr/versions/2.0.0.rc2) (2012/02)           | [2026/01](https://github.com/vcr/vcr)                        |
|          | ✅          | 4.2/10  | ✅    | [webmock](https://github.com/bblimke/webmock)                              | [3.26.1](https://rubygems.org/gems/webmock/versions/3.26.1) (2025/10)             | [3.26.1](https://rubygems.org/gems/webmock/versions/3.26.1) (2025/10)             | [2.0.0.beta2](https://rubygems.org/gems/webmock/versions/2.0.0.beta2) (2016/04)   | [2026/01](https://github.com/bblimke/webmock)                |

### CI quality gating

Use `--fail-if-critical` or `--fail-if-warning` to fail CI pipelines when dependencies exceed activity thresholds:

```bash
still_active --gemfile=Gemfile --fail-if-warning --json
```

### Data sources

- **Versions and release dates** from [RubyGems.org](https://rubygems.org)
- **Last commit date** from the [GitHub](https://docs.github.com/en/rest) or [GitLab](https://docs.gitlab.com/ee/api/) API
- **OpenSSF Scorecard** and **vulnerability counts** from Google's [deps.dev](https://deps.dev) API

### Configuration options

- `gemfile_path` uses bundler to detect the Gemfile in your working directory
- `output_format` auto-detects: coloured terminal on TTY, JSON when piped. Override with `--terminal`, `--markdown`, or `--json`
- `critical_warning_emoji` 🚩
- `futurist_emoji` 🔮
- `success_emoji` ✅
- `unsure_emoji` ❓
- `warning_emoji` ⚠️
- `safe_range_end` 1 (considered safe if last activity is at most 1 year ago)
- `warning_range_end` 3 (warns if last activity is between 1 and 3 years ago; beyond 3 is critical)

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. New versions are published automatically to [rubygems.org](https://rubygems.org) when a GitHub Release is created (via trusted publishing).

## Contributing

Bug reports and pull requests are welcome.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
