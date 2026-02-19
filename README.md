# `still_active`

**How do you know if your Ruby dependencies are still maintained?**

`bundle outdated` tells you version drift. `bundler-audit` catches known CVEs. Neither tells you whether anyone is still working on the thing. `still_active` checks maintenance activity, version freshness, security scores, and vulnerabilities for every gem in your Gemfile -- in one pass.

[![Gem Version](https://badge.fury.io/rb/still_active.svg)](https://badge.fury.io/rb/still_active)
![Code Quality analysis](https://github.com/SeanLF/still_active/actions/workflows/codeql-analysis.yml/badge.svg)
![RSpec](https://github.com/SeanLF/still_active/actions/workflows/rspec.yml/badge.svg)
![Rubocop analysis](https://github.com/SeanLF/still_active/actions/workflows/rubocop-analysis.yml/badge.svg)

```
Name                   Version          Activity  OpenSSF  Vulns
──────────────────────────────────────────────────────────────────
code-scanning-rubocop  0.6.1 (latest)   stale     3.1/10   0
debug                  1.11.1 (latest)  ok        5.2/10   0
faker                  3.6.0 (latest)   ok        7.4/10   0
rake                   13.3.1 (latest)  ok        5.3/10   0
rspec                  3.13.2 (latest)  ok        6.9/10   0
rubocop                1.84.2 (latest)  ok        5.9/10   0

12 gems: 12 up to date, 0 outdated · 11 active, 1 stale · 0 vulnerabilities
```

## Why `still_active`?

Most dependency tools answer one question. `still_active` answers all of them at once:

|                              | `bundle outdated` | `bundler-audit` | `libyear-bundler` | **`still_active`**           |
| ---------------------------- | ----------------- | --------------- | ----------------- | ---------------------------- |
| Outdated versions            | Yes               | -               | Yes               | **Yes**                      |
| Known vulnerabilities (CVEs) | -                 | Yes             | -                 | **Yes**                      |
| OpenSSF Scorecard            | -                 | -               | -                 | **Yes**                      |
| Last commit activity         | -                 | -               | -                 | **Yes**                      |
| GitLab support               | -                 | -               | -                 | **Yes**                      |
| CI quality gates             | -                 | Exit code       | -                 | **Yes**                      |
| Multiple output formats      | -                 | -               | -                 | **Terminal, JSON, Markdown** |
| Single command               | Yes               | Yes             | Yes               | **Yes**                      |

`still_active` tells you whether a dependency is outdated, insecure, _and_ abandoned -- not just one of the three.

## Installation

```bash
gem install still_active
```

## Quick Start

```bash
# audit your Gemfile (auto-detects output format)
still_active

# check specific gems
still_active --gems=rails,nokogiri,sidekiq

# CI pipeline: fail if any gem is critically stale
still_active --fail-if-critical

# markdown table for pull requests or documentation
still_active --markdown
```

## Usage

### Authentication

Tokens are read from `GITHUB_TOKEN` and `GITLAB_TOKEN` environment variables by default. Without a GitHub token you will most certainly get rate limited. The GitLab token is optional for public repos but required for private ones. CLI flags override the env vars.

### CLI options

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

### Output formats

**Terminal** (default on TTY) -- coloured table with summary line. Shown above.

**JSON** (default when piped) -- structured data for automation:

```bash
still_active --json --gems=rails,nokogiri
```

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

**Markdown** -- table for pull requests, documentation, or wikis:

```bash
still_active --markdown
```

| activity | up to date? | OpenSSF | vulns | name                  | version used     | latest version   | latest pre-release  | last commit |
| -------- | ----------- | ------- | ----- | --------------------- | ---------------- | ---------------- | ------------------- | ----------- |
| ⚠️       | ✅          | 3.1/10  | ✅    | code-scanning-rubocop | 0.6.1 (2022/02)  | 0.6.1 (2022/02)  | ❓                  | 2024/06     |
|          | ✅          | 5.2/10  | ✅    | debug                 | 1.11.1 (2025/12) | 1.11.1 (2025/12) | 1.0.0.rc2 (2021/09) | 2025/12     |
|          | ✅          | 7.4/10  | ✅    | faker                 | 3.6.0 (2026/01)  | 3.6.0 (2026/01)  | ❓                  | 2026/02     |

### CI quality gating

Use `--fail-if-critical` or `--fail-if-warning` to fail CI pipelines when dependencies exceed activity thresholds:

```bash
still_active --gemfile=Gemfile --fail-if-warning --json
```

### Activity thresholds

Activity is determined by the most recent signal across last commit date, latest release date, and latest pre-release date:

- **ok**: last activity within 1 year (configurable with `--safe-range-end`)
- **stale**: last activity between 1 and 3 years ago (configurable with `--warning-range-end`)
- **critical**: last activity over 3 years ago

### Data sources

- **Versions and release dates** from [RubyGems.org](https://rubygems.org)
- **Last commit date** from the [GitHub](https://docs.github.com/en/rest) or [GitLab](https://docs.gitlab.com/ee/api/) API
- **OpenSSF Scorecard** and **vulnerability counts** from Google's [deps.dev](https://deps.dev) API

### Configuration defaults

| Option                  | Default     | Description                                                      |
| ----------------------- | ----------- | ---------------------------------------------------------------- |
| `output_format`         | auto-detect | Coloured terminal on TTY, JSON when piped                        |
| `safe_range_end`        | 1 year      | Last activity within this range is "ok"                          |
| `warning_range_end`     | 3 years     | Last activity within this range is "stale"; beyond is "critical" |
| `simultaneous_requests` | 10          | Concurrent API requests                                          |

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. New versions are published automatically to [rubygems.org](https://rubygems.org) when a GitHub Release is created (via trusted publishing).

## Contributing

Bug reports and pull requests are welcome.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
