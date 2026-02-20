# `still_active`

**How do you know if your Ruby dependencies are still maintained?**

`bundle outdated` tells you version drift. `bundler-audit` catches known CVEs. Neither tells you whether anyone is still working on the thing. `still_active` checks maintenance activity, version freshness, security scores, vulnerabilities, libyear drift, and archived repos for every gem in your Gemfile -- with a composite health score per gem.

[![Gem Version](https://badge.fury.io/rb/still_active.svg)](https://badge.fury.io/rb/still_active)
![Code Quality analysis](https://github.com/SeanLF/still_active/actions/workflows/codeql-analysis.yml/badge.svg)
![RSpec](https://github.com/SeanLF/still_active/actions/workflows/rspec.yml/badge.svg)
![Rubocop analysis](https://github.com/SeanLF/still_active/actions/workflows/rubocop-analysis.yml/badge.svg)

```
Name                   Version          Activity  OpenSSF  Vulns  Health
───────────────────────────────────────────────────────────────────────────
code-scanning-rubocop  0.6.1 (latest)   stale     3.1/10   0      71/100
debug                  1.11.1 (latest)  ok        5.2/10   0      90/100
faker                  3.6.0 (latest)   ok        7.4/10   0      95/100
rake                   13.3.1 (latest)  ok        5.3/10   0      91/100
rspec                  3.13.2 (latest)  ok        6.9/10   0      94/100
rubocop                1.84.2 (latest)  ok        5.9/10   0      92/100

12 gems: 11 up to date, 0 outdated · 11 active, 1 stale · 0 vulnerabilities · health 93/100
Ruby 4.0.1 (latest)
```

## Why `still_active`?

Most dependency tools answer one question. `still_active` answers all of them at once:

|                              | `bundle outdated` | `bundler-audit` | `libyear-bundler` | **`still_active`**           |
| ---------------------------- | ----------------- | --------------- | ----------------- | ---------------------------- |
| Outdated versions            | Yes               | -               | Yes               | **Yes**                      |
| Known vulnerabilities (CVEs) | -                 | Yes             | -                 | **Yes** (with severity)      |
| OpenSSF Scorecard            | -                 | -               | -                 | **Yes**                      |
| Last commit activity         | -                 | -               | -                 | **Yes**                      |
| Libyear drift                | -                 | -               | Yes               | **Yes**                      |
| Composite health score       | -                 | -               | -                 | **Yes** (0-100)              |
| Archived repo detection      | -                 | -               | -                 | **Yes**                      |
| Yanked version detection     | -                 | -               | -                 | **Yes**                      |
| Ruby version freshness       | -                 | -               | -                 | **Yes** (EOL + libyear)      |
| Git/path/GH Packages sources | -                 | -               | -                 | **Yes**                      |
| GitLab support               | -                 | -               | -                 | **Yes**                      |
| CI quality gates             | -                 | Exit code       | -                 | **Yes** (4 modes)            |
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

# CI pipeline: fail if any gem is critically stale or has low health
still_active --fail-if-critical --fail-below-score=50

# ignore specific gems in CI checks
still_active --fail-if-warning --ignore=legacy_gem,internal_gem

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
        --fail-below-score=SCORE     Exit 1 if any gem health score is below threshold
        --ignore=GEM,GEM2,...        Exclude gems from pass/fail checks (still shown in output)
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
  "gems": {
    "rails": {
      "source_type": "rubygems",
      "latest_version": "8.1.2",
      "repository_url": "https://github.com/rails/rails",
      "last_commit_date": "2026-02-19 09:39:03 UTC",
      "archived": false,
      "scorecard_score": 5.7,
      "vulnerability_count": 0,
      "health_score": 88
    },
    "nokogiri": {
      "source_type": "rubygems",
      "latest_version": "1.19.1",
      "repository_url": "https://github.com/sparklemotion/nokogiri",
      "last_commit_date": "2026-02-17 19:13:22 UTC",
      "archived": false,
      "scorecard_score": 6.5,
      "vulnerability_count": 0,
      "health_score": 90
    }
  },
  "ruby": {
    "version": "4.0.1",
    "eol": false,
    "latest_version": "4.0.1",
    "libyear": 0.0
  }
}
```

**Markdown** -- table for pull requests, documentation, or wikis:

```bash
still_active --markdown
```

| activity | up to date? | OpenSSF | vulns | name     | version used | latest version   | latest pre-release   | last commit | libyear | health |
| -------- | ----------- | ------- | ----- | -------- | ------------ | ---------------- | -------------------- | ----------- | ------- | ------ |
|          | ❓          | 5.2/10  | ✅    | debug    | ❓           | 1.11.1 (2025/12) | 1.0.0.rc2 (2021/09)  | 2025/12     | -       | 86/100 |
|          | ❓          | 6.5/10  | ✅    | nokogiri | ❓           | 1.19.1 (2026/02) | 1.18.0.rc1 (2024/12) | 2026/02     | -       | 90/100 |
|          | ❓          | 5.7/10  | ✅    | rails    | ❓           | 8.1.2 (2026/01)  | 8.1.0.rc1 (2025/10)  | 2026/02     | -       | 88/100 |

**Ruby 4.0.1** (latest) ✅

### CI quality gating

Use exit-code flags to fail CI pipelines based on dependency health:

```bash
# fail on critically stale or archived gems
still_active --fail-if-critical --json

# fail on any stale, critical, or archived gem
still_active --fail-if-warning --json

# fail if any gem's health score drops below a threshold
still_active --fail-below-score=50 --json

# combine flags and exclude known exceptions
still_active --fail-if-warning --fail-below-score=50 --ignore=legacy_gem --json
```

### Activity thresholds

Activity is determined by the most recent signal across last commit date, latest release date, and latest pre-release date:

- **ok**: last activity within 1 year (configurable with `--safe-range-end`)
- **stale**: last activity between 1 and 3 years ago (configurable with `--warning-range-end`)
- **critical**: last activity over 3 years ago

### Data sources

- **Versions and release dates** from [RubyGems.org](https://rubygems.org) or [GitHub Packages](https://docs.github.com/en/packages)
- **Last commit date and archived status** from the [GitHub](https://docs.github.com/en/rest) or [GitLab](https://docs.gitlab.com/ee/api/) API
- **OpenSSF Scorecard**, **vulnerability counts**, and **CVSS severity** from Google's [deps.dev](https://deps.dev) API
- **Ruby version freshness** from [endoflife.date](https://endoflife.date)

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
