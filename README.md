# `still_active`

**How do you know the dependencies you ship are still maintained?**

[![Gem Version](https://badge.fury.io/rb/still_active.svg)](https://rubygems.org/gems/still_active)

[Install](#installation) · [Quick start](#quick-start) · [GitHub Action & CI](#github-action--ci) · [Cross-ecosystem](#cross-ecosystem-audit) · [Configuration](#configuration) · [Rules](docs/rules.md)

Your package manager tells you what's outdated and what has a known CVE. Neither tells you whether anyone's still working on the thing. An abandoned dependency is a quiet liability: when it finally breaks or a vulnerability lands, there's no release coming and no one to ping, and you find out at the worst time.

`still_active` flags that risk before it bites, across your whole dependency graph: archived repos, no release in years, low OpenSSF scores, unfixable vulnerabilities, and the poison-pill case where a dormant package holds one of your deps below its own security patch. Native on **Ruby** gems; **npm, PyPI, Cargo, Go, Maven, and NuGet** via a CycloneDX SBOM.

```
Name            Version          Activity  OpenSSF  Vulns  License
────────────────────────────────────────────────────────────────────
backbone-rails  1.2.3 (latest)   archived  2.6/10   0      -
  ↳ run with --alternatives for maintained replacements
nokogiri        1.19.4 (latest)  ok        5.9/10   0      MIT
paperclip       6.1.0 (latest)   archived  2/10     0      MIT
  ↳ poison: caps terrapin ~> 0.6.0 (1 major behind, latest 1.x)
  ↳ run with --alternatives for maintained replacements
rake            13.4.2 (latest)  ok        5.5/10   0      MIT

4 gems: 4 up to date · 2 active, 2 archived · 0 vulnerabilities · 1 poison-pill
Ruby 4.0.5 (latest)
```

## Why `still_active`?

No package ecosystem's standard tooling answers "is anyone still maintaining this?" `npm audit`, `cargo audit`, `pip-audit`, and `bundler-audit` find known CVEs; the `outdated` commands find version drift. None tell you a dependency's upstream is archived, hasn't shipped in three years, or is holding one of your deps below its security fix. That maintenance gap is what `still_active` fills. It's **complementary to**, not a replacement for, the tools you already run.

On Ruby, where it runs natively:

|                              | `bundle outdated` | `bundler-audit`        | `libyear-bundler` | **`still_active`**       |
| ---------------------------- | ----------------- | ---------------------- | ----------------- | ------------------------ |
| Outdated versions            | Yes               | -                      | Yes               | Yes                      |
| Known vulnerabilities (CVEs) | -                 | Yes (ruby-advisory-db) | -                 | Yes (deps.dev + OSV + ruby-advisory-db) |
| Libyear drift                | -                 | -                      | Yes               | Yes                      |
| **Last-commit activity**     | -                 | -                      | -                 | **Yes**                  |
| **Archived repo detection**  | -                 | -                      | -                 | **Yes**                  |
| **OpenSSF Scorecard**        | -                 | -                      | -                 | **Yes**                  |
| **Poison-pill / below-the-fix** | -              | -                      | -                 | **Yes**                  |
| **Cross-ecosystem** (npm/PyPI/Cargo/Go/Maven/NuGet) | - | -              | -                 | **Yes** (`--sbom`)       |
| CI quality gates             | -                 | Exit code              | -                 | Yes (6 gate flags)       |

With `bundler-audit` installed alongside, `still_active` merges its `ruby-advisory-db` advisories with its own deps.dev + OSV sources, so running both no longer means reconciling two vuln counts by hand.

## Installation

```bash
gem install still_active
```

Requires an actively-maintained Ruby (the gemspec floor tracks Ruby's [EOL schedule](https://endoflife.date/ruby)). You don't have to run it *on* the Ruby you audit: it reports on the version pinned in `Gemfile.lock`, so run it from any current Ruby and it still flags an EOL target.

## Quick start

```bash
# audit your Gemfile (auto-detects output format)
still_active

# cross-ecosystem: audit any CycloneDX SBOM (npm, PyPI, Cargo, Go, Maven, NuGet)
syft dir:. -o cyclonedx-json > sbom.json && still_active --sbom=sbom.json

# fail CI if any gem is critically stale or vulnerable
still_active --fail-if-critical --fail-if-vulnerable

# markdown table for a pull request
still_active --markdown
```

Full flags: [`docs/cli.md`](docs/cli.md). Tokens for private registries and self-hosted forges: [`docs/authentication.md`](docs/authentication.md).

## GitHub Action & CI

The [`still_active-action`](https://github.com/SeanLF/still_active-action) uploads findings to your **GitHub Security tab** as SARIF, with inline PR annotations on `Gemfile.lock`:

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

Gate the build on what you care about (all off by default, so nothing breaks until you opt in):

```bash
still_active --fail-if-critical              # upstream critically stale or archived
still_active --fail-if-vulnerable            # any known vulnerability (or =low|medium|high|critical)
still_active --fail-if-outdated=3            # more than 3 libyears behind latest
still_active --fail-if-poison                # a dormant package caps a dep below its latest major
still_active --fail-if-language-ceiling      # a pin strands you on an EOL language runtime
```

For PR review, `--baseline` reports only what got *worse* since a saved snapshot and exits 1 on any regression:

```bash
still_active --json > /tmp/main.json && still_active --baseline=/tmp/main.json
```

Rule reference (SA001-SA009), suppression, and composing with `dependency-review-action`: [`docs/rules.md`](docs/rules.md), [`docs/ci.md`](docs/ci.md). This repo audits itself every push, so you can browse live findings in its [Code Scanning tab](https://github.com/SeanLF/still_active/security/code-scanning?query=tool%3Astill_active+is%3Aopen).

## Cross-ecosystem audit

Point `--sbom` at a CycloneDX SBOM (from [Syft](https://github.com/anchore/syft), Trivy, or any producer) and `still_active` assesses `npm`, `pypi`, `cargo`, `go`, `maven`, and `nuget` packages the same way it does gems, via [deps.dev](https://deps.dev) and [ecosyste.ms](https://ecosyste.ms). Most signals apply everywhere; a few are deliberately scoped (detail in [`docs/rules.md`](docs/rules.md)):

| Signal (rule) | Ruby (native) | `--sbom` (cross-ecosystem) |
| ------------- | ------------- | -------------------------- |
| Archived (SA001), no recent release (SA002), low OpenSSF (SA005), libyear (SA004) | Yes | Yes (all six ecosystems) |
| Vulnerabilities (SA003) | deps.dev + OSV + ruby-advisory-db | deps.dev + OSV |
| &nbsp;&nbsp;↳ "below the fix" (a dead package pins a vulnerable dep) | Yes | npm, Cargo, PyPI |
| Poison-pill (SA008) | rubygems | PyPI (flat resolution only) |
| Language-runtime ceiling (SA009) | Ruby | Python |
| Ruby EOL (SA006), yanked (SA007) | Yes | n/a |

The SBOM is treated as **untrusted input**: only ecosystem/name/version are read, repositories are resolved from deps.dev (never a URL the SBOM supplies), and anything it can't assess is surfaced in an `unassessable` list rather than dropped or faked as `ok`. The play is **maintenance**, not CVE scanning, so compose Trivy/Grype for full vulnerability coverage.

## Output formats

Auto-detected: a coloured terminal table on a TTY (above), JSON when piped. Or ask explicitly.

<details>
<summary><strong>JSON</strong> (<code>--json</code>): a versioned, contract-tested schema for automation</summary>

```json
{
  "gems": {
    "nested_form": {
      "source_type": "git",
      "version_used": "0.3.2",
      "repository_url": "https://github.com/ryanb/nested_form",
      "archived": true,
      "scorecard_score": 3.3,
      "vulnerability_count": 0,
      "status": "archived"
    }
  },
  "ruby": { "version": "4.0.5", "eol": false, "latest_version": "4.0.5" }
}
```

Fields are documented in [`docs/schema.md`](docs/schema.md).
</details>

<details>
<summary><strong>Markdown</strong> (<code>--markdown</code>): a table for pull requests, docs, or wikis</summary>

| activity | up to date? | OpenSSF | vulns | name | version | last commit |
| -------- | ----------- | ------- | ----- | ---- | ------- | ----------- |
|          | ✅          | 5.9/10  | ✅    | [nokogiri](https://github.com/sparklemotion/nokogiri) | 1.19.4 | 2026/06 |
| 🚩       | ✅          | 2/10    | ✅    | [paperclip](https://github.com/thoughtbot/paperclip) | 6.1.0 | 2021/03 |
</details>

**SARIF** feeds GitHub Code Scanning (see [GitHub Action & CI](#github-action--ci)). **CycloneDX** (`--cyclonedx`) emits a standards-track SBOM so your graph and `still_active`'s signals flow into Trivy, Dependency-Track, or Snyk.

## Configuration

A committed `.still_active.yml` keeps policy in version control and replaces the blunt `--ignore=GEM` (which mutes *every* gate for a gem) with granular, expiring suppression:

```yaml
fail_if_vulnerable: high        # true, or a minimum severity: low|medium|high|critical
fail_if_poison: warning         # true (=warning), or a tier: note|warning|critical

ignore:
  # accept ONE advisory by id; a different or new CVE on nokogiri still fails
  - advisory: CVE-2024-1234
    gem: nokogiri
    reason: "no fix released; not reachable from our code path"
    expires: 2026-09-01         # re-surfaces as a normal failure after this date
```

A vulnerability suppression must name an advisory id (so a new CVE is never pre-silenced), an `expires:` date makes accepted risk re-surface instead of rotting, and a suppressed finding still shows in output (and as a dismissed SARIF entry). Full semantics, thresholds, and transitive behaviour: [`docs/configuration.md`](docs/configuration.md).

## Data sources

Release dates and licenses from [RubyGems](https://rubygems.org) / [GitHub Packages](https://docs.github.com/en/packages) / [Artifactory](https://jfrog.com/artifactory/); repo activity from the [GitHub](https://docs.github.com/en/rest) / [GitLab](https://docs.gitlab.com/ee/api/) / [Codeberg](https://forgejo.org/docs/latest/user/api-usage/) API, or [ecosyste.ms](https://ecosyste.ms) tokenless ([CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)); OpenSSF Scorecard and CVSS from [deps.dev](https://deps.dev); advisory severities and fixed-version ranges from [OSV](https://osv.dev) (CVSS-4 scoring needs the optional [`cvss-suite`](https://rubygems.org/gems/cvss-suite)); extra advisories from [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db); runtime EOL from [endoflife.date](https://endoflife.date).

## Development

`bin/setup` installs dependencies and wires git hooks; `rake` runs the full lint + test suite. A pre-push hook runs `rake` automatically. Releases publish to [rubygems.org](https://rubygems.org) automatically on a GitHub Release (trusted publishing). See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Open source under the [MIT License](https://opensource.org/licenses/MIT).
