# `still_active`

**How do you know the dependencies you ship are still maintained?**

[![Gem Version](https://badge.fury.io/rb/still_active.svg)](https://badge.fury.io/rb/still_active)
[![RSpec](https://github.com/SeanLF/still_active/actions/workflows/rspec.yml/badge.svg)](https://github.com/SeanLF/still_active/actions/workflows/rspec.yml)
[![GitHub Action](https://img.shields.io/badge/Marketplace-still__active--action-2ea44f?logo=github)](https://github.com/marketplace/actions/still_active)

[Install](#installation) · [Quick start](#quick-start) · [GitHub Action & CI](#github-action--ci) · [Cross-ecosystem](#cross-ecosystem-audit) · [Configuration](#configuration) · [Rules](docs/rules.md)

Your package manager tells you what's outdated and what has a known CVE. Neither tells you whether anyone's still working on the thing. And an abandoned dependency is a quiet liability: when it finally breaks or a vulnerability lands, there's no release coming and no one to ping, and you find out at the worst possible time.

`still_active` surfaces that risk before it bites, across your whole dependency graph: archived repos, no release in years, low OpenSSF scores, vulnerabilities with no fix available, and the poison-pill case where a dormant package pins one of your dependencies below its own security patch. It runs natively on **Ruby** gems, audits **npm, PyPI, Cargo, Go, Maven, and NuGet** packages from a CycloneDX SBOM, and folds in the outdated / CVE / libyear signals, so it's one report instead of three.

```
Name                    Version          Activity  OpenSSF  Vulns  License
──────────────────────────────────────────────────────────────────────────────
async                   2.36.0 (latest)  ok        7.1/10   0      MIT
backbone-rails          1.2.3 (latest)   archived  3.6/10   0      MIT
bootstrap-slider-rails  9.8.0 (latest)   critical  -        0      MIT
gitlab-markup           2.0.0 (latest)   ok        -        0      MIT
local_gem               0.1.0 (path)     -         -        0      -
nested_form             0.3.2 (git)      archived  3.3/10   0      MIT
remotipart              1.4.4 (git)      critical  3.1/10   0      MIT

7 gems: 4 up to date, 0 outdated · 2 active, 2 stale, 2 archived · 0 vulnerabilities
Ruby 4.0.1 (latest)
```

## Why `still_active`?

No package ecosystem's standard tooling answers "is anyone still maintaining this?" `npm audit`, `cargo audit`, `pip-audit`, and `bundler-audit` find known CVEs; the `outdated` commands find version drift. None of them tell you a dependency's upstream is archived, hasn't shipped in three years, or that a dormant package is holding one of your deps below its security fix. That maintenance gap is what `still_active` fills, and it's **complementary to**, not a replacement for, the tools you already run.

On Ruby, where it runs natively, here's how it slots in alongside them:

|                              | `bundle outdated` | `bundler-audit`        | `libyear-bundler` | **`still_active`**       |
| ---------------------------- | ----------------- | ---------------------- | ----------------- | ------------------------ |
| Outdated versions            | Yes               | -                      | Yes               | Yes                      |
| Known vulnerabilities (CVEs) | -                 | Yes (ruby-advisory-db) | -                 | Yes (deps.dev + OSV + ruby-advisory-db) |
| Libyear drift                | -                 | -                      | Yes               | Yes                      |
| **Last commit activity**     | -                 | -                      | -                 | **Yes**                  |
| **Archived repo detection**  | -                 | -                      | -                 | **Yes**                  |
| **OpenSSF Scorecard**        | -                 | -                      | -                 | **Yes**                  |
| **Poison-pill / below-the-fix** | -              | -                      | -                 | **Yes**                  |
| **Ruby version freshness**   | -                 | -                      | -                 | **Yes** (EOL + libyear)  |
| **Cross-ecosystem** (npm/PyPI/Cargo/Go/Maven/NuGet) | - | -              | -                 | **Yes** (`--sbom`)       |
| CI quality gates             | -                 | Exit code              | -                 | Yes (6 gate flags)       |

When `bundler-audit` is installed alongside, `still_active` reads its `ruby-advisory-db` checkout and merges the advisories with its own deps.dev + OSV sources (deduplicated, each tagged with its `source`), so running both no longer means reconciling two vuln counts by hand.

## Installation

```bash
gem install still_active
```

**Requires an actively-maintained Ruby** (the gemspec floor tracks Ruby's [EOL schedule](https://endoflife.date/ruby)). You don't have to run it *on* the Ruby you're auditing, though: it reports on the version your project pins in `Gemfile.lock`, so run it from any current Ruby and it still flags an EOL target.

## Quick start

```bash
# audit your Gemfile (auto-detects output format)
still_active

# check specific gems
still_active --gems=rails,nokogiri,sidekiq

# fail CI if any gem is critically stale or vulnerable
still_active --fail-if-critical --fail-if-vulnerable

# markdown table for a pull request
still_active --markdown
```

Full flag reference: [`docs/cli.md`](docs/cli.md). Private registries and self-hosted forges (GitHub / GitLab / Codeberg / Artifactory tokens): [`docs/authentication.md`](docs/authentication.md).

## GitHub Action & CI

Run `still_active` in CI with the [`still_active-action`](https://github.com/SeanLF/still_active-action), which uploads findings to your **GitHub Security tab** as SARIF (with inline PR annotations on `Gemfile.lock`):

```yaml
permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ruby/setup-ruby@v1
        with: { ruby-version: '3.4' }
      - uses: SeanLF/still_active-action@v0
        with:
          github-token: ${{ github.token }}
          sarif: still_active.sarif.json
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: still_active.sarif.json }
```

**Fail the build on what you care about** (all off by default, so nothing breaks until you opt in):

```bash
still_active --fail-if-critical              # a gem's upstream is critically stale or archived
still_active --fail-if-vulnerable            # any known vulnerability (or =low|medium|high|critical)
still_active --fail-if-outdated=3            # more than 3 libyears behind latest
still_active --fail-if-poison                # a dormant package caps a dep below its latest major (or =TIER)
still_active --fail-if-language-ceiling      # a pin strands you on an EOL language runtime
still_active --fail-if-warning --ignore=legacy_gem   # combine, and exempt known exceptions
```

**PR review, "what got worse?"** `--baseline` compares against a saved snapshot and reports only regressions (new vulns, newly-archived deps, scorecard drops crossing 7.0, libyear growth, Ruby newly EOL), exiting 1 on any. A Dependabot/Renovate-authored run leads with a one-line narrative ("`rack` 2.0.0 → 2.0.6").

```bash
still_active --json > /tmp/main.json          # capture on main
still_active --baseline=/tmp/main.json        # compare on your branch
```

Rule reference (SA001-SA009), suppression, and composing with GitHub's `dependency-review-action`: see [`docs/rules.md`](docs/rules.md) and [`docs/ci.md`](docs/ci.md). This repo audits itself on every push, so you can browse live findings in its [Code Scanning tab](https://github.com/SeanLF/still_active/security/code-scanning?query=tool%3Astill_active+is%3Aopen).

## Cross-ecosystem audit

The maintenance lens isn't Ruby-only. Point `--sbom` at a CycloneDX SBOM (from [Syft](https://github.com/anchore/syft), Trivy, or any producer) and `still_active` assesses `npm`, `pypi`, `cargo`, `go`, `maven`, and `nuget` packages the same way it does gems, sourcing signals from [deps.dev](https://deps.dev) and [ecosyste.ms](https://ecosyste.ms):

```bash
syft dir:. -o cyclonedx-json > sbom.json
still_active --sbom=sbom.json                 # JSON, keyed "ecosystem/name@version"
```

Most signals apply everywhere; a few are deliberately scoped (full detail in [`docs/rules.md`](docs/rules.md)):

| Signal (rule) | Ruby (native) | `--sbom` (cross-ecosystem) |
| ------------- | ------------- | -------------------------- |
| Archived repo (SA001), no recent release (SA002), low OpenSSF (SA005), libyear (SA004) | Yes | Yes (all six ecosystems) |
| Vulnerabilities (SA003) | Yes (deps.dev + OSV + ruby-advisory-db) | Yes (deps.dev + OSV) |
| &nbsp;&nbsp;↳ "below the fix" (a dead package pins a vulnerable dep) | Yes | npm, Cargo, PyPI (patch precision) |
| Poison-pill / compatibility ceiling (SA008) | Yes (rubygems) | PyPI (flat resolution only) |
| Language-runtime ceiling (SA009) | Yes (`ruby_version`) | Python (`requires_python`) |
| Ruby EOL (SA006), yanked version (SA007) | Yes | n/a |

The SBOM is treated as **untrusted input**: only ecosystem/name/version are read from it, the repository is resolved from deps.dev (never a URL the SBOM supplies), and anything it can't assess is surfaced in an `unassessable` list rather than silently dropped or faked as `ok`. The differentiated play is **maintenance**, not vulnerability scanning, so compose Trivy/Grype for full CVE coverage.

## Output formats

Auto-detected: a coloured terminal table on a TTY (shown above), JSON when piped. Or ask explicitly:

<details>
<summary><strong>JSON</strong> (<code>--json</code>): structured data for automation</summary>

```json
{
  "gems": {
    "async": {
      "source_type": "rubygems",
      "version_used": "2.36.0",
      "latest_version": "2.36.0",
      "repository_url": "https://github.com/socketry/async",
      "last_commit_date": "2026-01-22 04:09:48 UTC",
      "archived": false,
      "scorecard_score": 7.1,
      "vulnerability_count": 0,
      "license": "MIT",
      "libyear": 0.0
    },
    "nested_form": {
      "source_type": "git",
      "version_used": "0.3.2",
      "archived": true,
      "scorecard_score": 3.3,
      "vulnerability_count": 0
    }
  },
  "ruby": { "version": "4.0.1", "eol": false, "latest_version": "4.0.1", "libyear": 0.0 }
}
```

The `--json` output is a versioned, contract-tested schema; fields are documented in [`docs/schema.md`](docs/schema.md).
</details>

<details>
<summary><strong>Markdown</strong> (<code>--markdown</code>): a table for pull requests, docs, or wikis</summary>

| activity | up to date? | OpenSSF | vulns | name | version used | last commit | libyear | license |
| -------- | ----------- | ------- | ----- | ---- | ------------ | ----------- | ------- | ------- |
|          | ✅          | 7.1/10  | ✅    | [async](https://github.com/socketry/async) | 2.36.0 (2026/01) | 2026/01 | 0.0y | MIT |
| 🚩       | ✅          | 3.6/10  | ✅    | [backbone-rails](https://github.com/aflatter/backbone-rails) | 1.2.3 (2016/02) | 2016/02 | 0.0y | MIT |
</details>

**SARIF** feeds GitHub Code Scanning (see [GitHub Action & CI](#github-action--ci)). **CycloneDX** (`--cyclonedx`, 1.6 by default or `--cyclonedx-version=1.7`) emits a standards-track SBOM so your graph and `still_active`'s signals flow into Trivy, Dependency-Track, or Snyk.

## Configuration

A committed `.still_active.yml` in the project root keeps your policy in version control and replaces the blunt `--ignore=GEM` (which mutes *every* gate for a gem) with granular, auditable, expiring suppression:

```yaml
# policy defaults
fail_if_critical: true
fail_if_vulnerable: high        # true, or a minimum severity: low|medium|high|critical
fail_if_outdated: 3             # libyears
fail_if_poison: warning         # true (=warning), or a tier: note|warning|critical
direct_only: true               # audit only declared deps, not the full transitive graph

# fold in bundler-audit's accepted-advisory list instead of maintaining two files
import: [.bundler-audit.yml]

ignore:
  # accept ONE advisory by id; a different/new CVE on nokogiri still fails
  - advisory: CVE-2024-1234
    gem: nokogiri
    reason: "no fix released; not reachable from our code path"
    expires: 2026-09-01         # re-surfaces as a normal failure after this date

  # accept staleness on a vendored gem, but still fail if it gets a CVE
  - gem: legacy_thing
    signal: activity            # activity | vulnerability | libyear | poison | language_ceiling
    reason: "vendored, intentionally frozen"
```

A vulnerability suppression **must** name an advisory id (so a newly disclosed CVE is never pre-silenced), an `expires:` date makes accepted risk re-surface instead of rotting, and a suppressed finding still appears in output (and as a dismissed SARIF entry), so suppression accepts a risk without hiding it. Precedence is CLI flag > env var > config file > default; secrets and paths are never read from the file. Full semantics, activity thresholds, and transitive-dependency behaviour: [`docs/configuration.md`](docs/configuration.md).

## Data sources

- **Versions, release dates, licenses** from [RubyGems.org](https://rubygems.org), [GitHub Packages](https://docs.github.com/en/packages), or [JFrog Artifactory](https://jfrog.com/artifactory/)
- **Last commit + archived status** from the [GitHub](https://docs.github.com/en/rest), [GitLab](https://docs.gitlab.com/ee/api/), or [Forgejo/Gitea](https://forgejo.org/docs/latest/user/api-usage/) API, or from [ecosyste.ms](https://ecosyste.ms) for GitHub repos with no token ([CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/))
- **OpenSSF Scorecard, vulnerability counts, CVSS** from Google's [deps.dev](https://deps.dev) (also the cross-ecosystem source on `--sbom`)
- **Advisory severity + fixed-version ranges** from [OSV](https://osv.dev); a CVSS-4-only advisory scores only if the optional [`cvss-suite`](https://rubygems.org/gems/cvss-suite) gem is installed (the gate still fires on the OSV/GHSA label without it)
- **Extra advisories** from [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db) (when `bundler-audit` is installed), **Ruby EOL** from [endoflife.date](https://endoflife.date), **alternative leads** from [rubytoolbox/catalog](https://github.com/rubytoolbox/catalog)

## Development

Run `bin/setup` to install dependencies and wire git hooks, then `rake` for the full lint + test suite (`rake spec` / `rake rubocop` for one). `bin/console` opens an interactive prompt. A pre-push hook runs `rake` automatically (skip with `--no-verify`). New versions publish to [rubygems.org](https://rubygems.org) automatically when a GitHub Release is created (via trusted publishing).

## Contributing

Bug reports and pull requests are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Open source under the [MIT License](https://opensource.org/licenses/MIT).
