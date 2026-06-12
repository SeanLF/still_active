# `still_active`

**How do you know if your Ruby dependencies are still maintained?**

`bundle outdated` tells you version drift. `bundler-audit` catches known CVEs. Neither tells you whether anyone is still working on the thing. `still_active` checks maintenance activity, version freshness, security scores, vulnerabilities, libyear drift, and archived repos for every gem in your Gemfile.

Findings ship as **terminal / markdown / JSON / SARIF / CycloneDX** — SARIF lands in your GitHub Security tab and as inline PR annotations on `Gemfile.lock`; CycloneDX feeds Trivy / Dependency-Track / Snyk. PR mode (`--baseline=FILE`) reports only what got worse since main, so reviewers see one line ("`vcr` newly archived") instead of an absolute snapshot of every dep.

[![Gem Version](https://badge.fury.io/rb/still_active.svg)](https://badge.fury.io/rb/still_active)
[![GitHub Action](https://img.shields.io/badge/Marketplace-still__active--action-2ea44f?logo=github)](https://github.com/marketplace/actions/still_active)
![Code Quality analysis](https://github.com/SeanLF/still_active/actions/workflows/codeql-analysis.yml/badge.svg)
![RSpec](https://github.com/SeanLF/still_active/actions/workflows/rspec.yml/badge.svg)
![Rubocop analysis](https://github.com/SeanLF/still_active/actions/workflows/rubocop-analysis.yml/badge.svg)

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

`still_active` is **complementary to** -- not a replacement for -- the established Ruby tooling. `bundle outdated`, `bundler-audit`, and `libyear-bundler` are purpose-built and battle-tested at what they do. `still_active` answers a different question: **is anyone still maintaining this gem?** -- and folds in the version/CVE/libyear signals so you get one report instead of three.

|                              | `bundle outdated` | `bundler-audit`        | `libyear-bundler` | **`still_active`**       |
| ---------------------------- | ----------------- | ---------------------- | ----------------- | ------------------------ |
| Outdated versions            | Yes               | -                      | Yes               | Yes                      |
| Known vulnerabilities (CVEs) | -                 | Yes (ruby-advisory-db) | -                 | Yes (deps.dev + ruby-advisory-db) |
| Libyear drift                | -                 | -                      | Yes               | Yes                      |
| **Last commit activity**     | -                 | -                      | -                 | **Yes**                  |
| **Archived repo detection**  | -                 | -                      | -                 | **Yes**                  |
| **OpenSSF Scorecard**        | -                 | -                      | -                 | **Yes**                  |
| **Yanked version detection** | -                 | -                      | -                 | **Yes**                  |
| **Ruby version freshness**   | -                 | -                      | -                 | **Yes** (EOL + libyear)  |
| GitLab support               | -                 | -                      | -                 | Yes                      |
| CI quality gates             | -                 | Exit code              | -                 | Yes (4 flags)            |
| Output formats               | Text              | Text                   | Text              | Terminal, JSON, Markdown, SARIF, CycloneDX |

The bolded rows are the gap `still_active` fills: nobody else answers "is the maintainer still around?" The CVE column is worth a closer look: `bundler-audit` reads `ruby-advisory-db` and `still_active` reads `deps.dev`, which sometimes diverge. **If `bundler-audit` is installed alongside `still_active`, we read its `ruby-advisory-db` checkout too and merge the results** (deduplicated, each advisory tagged with its `source`) — so running both no longer means reconciling two different vuln counts by hand.

## Installation

```bash
gem install still_active
```

**Requires an actively-maintained Ruby.** The gemspec's `required_ruby_version` floor tracks Ruby's [EOL schedule](https://endoflife.date/ruby); running a maintenance auditor on an unmaintained runtime would be a bit rich. You don't have to run it *on* the Ruby you're auditing, though: still_active reports on the version your project pins in `Gemfile.lock`, so run it from any current Ruby (locally, in CI, or via the [`still_active-action`](https://github.com/SeanLF/still_active-action)) and it will still flag an EOL target.

## Quick Start

```bash
# audit your Gemfile (auto-detects output format)
still_active

# check specific gems
still_active --gems=rails,nokogiri,sidekiq

# CI pipeline: fail if any gem is critically stale or has vulnerabilities
still_active --fail-if-critical --fail-if-vulnerable

# ignore specific gems in CI checks
still_active --fail-if-warning --ignore=legacy_gem,internal_gem

# markdown table for pull requests or documentation
still_active --markdown
```

## Usage

### Authentication

`still_active` discovers a GitHub token in this order:

1. `--github-oauth-token=TOKEN` CLI flag
2. `GITHUB_TOKEN` environment variable (CI convention)
3. `GH_TOKEN` environment variable (`gh` CLI convention)
4. `gh auth token` (if `gh` is installed and authenticated)

Without a token, GitHub API calls are unauthenticated and rate-limited to 60 requests/hour — you will hit the limit on anything beyond a handful of gems. With a token the limit is 5000 requests/hour. When a rate-limit response comes back with a reset that's near (within 60 seconds, typically a secondary/burst limit that the concurrent fan-out can trip even with a token), still_active waits it out and retries rather than dropping that gem's signals; a far-off reset (you've exhausted the hourly limit) isn't waited out, so add a token or run less often.

GitLab cascade mirrors GitHub: `--gitlab-token` → `GITLAB_TOKEN` → `glab auth status --show-token`. Optional for public repos, required for private ones.

Forgejo/Codeberg (the rare gem whose canonical `source_code_uri` is `codeberg.org`) is read anonymously by default; set `STILL_ACTIVE_FORGEJO_TOKEN` (or `CODEBERG_TOKEN`) only to raise the rate limit or reach a private repo. There is no CLI flag, since Codeberg has no ubiquitous CLI to borrow a token from the way `gh`/`glab` do.

Artifactory auth prefers Bundler's per-source credentials (`Bundler.settings` for the source URL or hostname) so private registries work the same way `bundle install` does and multiple hosts need no extra configuration. If none are set, still_active falls back to a global token via `--artifactory-token` or `STILL_ACTIVE_ARTIFACTORY_TOKEN`; that path requires `--artifactory-host` / `STILL_ACTIVE_ARTIFACTORY_HOST` to prevent sending the token to an unexpected host from the lockfile. Use `user:password` in Bundler settings for Basic auth, or a bare token for Bearer auth. Required for private JFrog gem registries (`.jfrog.io`).

When providing the artifactory token via flag or env, you must also set `--artifactory-host` or `STILL_ACTIVE_ARTIFACTORY_HOST` to the expected registry hostname (e.g. `my-org.jfrog.io`). still_active only sends the token to a matching host, so a lockfile cannot redirect it elsewhere to prevent leaking the token to an unverified host. Providing a token/host in this manner will work only for a single-host. To support multiple Artifactory hosts, use Bundler's credentials per source URL or hostname (`bundle config set credentials.my-org.jfrog.io user:pass`).

### CLI options

```text
Usage: still_active [options]

        all flags are optional

        --gemfile=GEMFILE            path to gemfile
        --gems=GEM,GEM2,...          Gem(s)
        --terminal                   Coloured terminal output (default in TTY)
        --markdown                   Markdown table output
        --json                       JSON output (default when piped)
        --alternatives               Suggest maintained alternatives (Ruby Toolbox leads) for archived/critical gems
        --unreleased-commits         Count commits on the default branch since the latest release (GitHub only; opt-in)
        --direct-only                Audit only direct (declared) deps, not the full transitive graph
        --sarif[=PATH]               SARIF 2.1.0 output for GitHub Code Scanning
        --cyclonedx[=PATH]           CycloneDX SBOM output (stdout, or a file path)
        --cyclonedx-version=VERSION  CycloneDX spec version: 1.6 (default) or 1.7
        --baseline=PATH              Compare current state to baseline JSON; emit markdown deltas
        --github-oauth-token=TOKEN   GitHub OAuth token to make API calls
        --gitlab-token=TOKEN         GitLab personal access token for API calls
        --artifactory-token=TOKEN    Artifactory token for private gem registry API calls
        --artifactory-host=HOST      Artifactory host allowed to receive the global token (e.g. my-org.jfrog.io)
        --simultaneous-requests=QTY  Number of simultaneous requests made
        --safe-range-end=YEARS       maximum years since last release considered safe, no warning (default 1.5)
        --warning-range-end=YEARS    maximum years since last release that triggers a warning, beyond this is critical (default 3)
        --fail-if-critical           Exit 1 if any gem has critical activity warning
        --fail-if-warning            Exit 1 if any gem has warning or critical activity warning
        --fail-if-vulnerable[=SEVERITY]
                                     Exit 1 if any gem has vulnerabilities (optionally at or above SEVERITY)
        --fail-if-outdated=LIBYEARS  Exit 1 if any gem exceeds LIBYEARS behind latest
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
still_active --json --gemfile=spec/still_active/edge_case_gemfile/Gemfile
```

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
      "repository_url": "https://github.com/ryanb/nested_form",
      "last_commit_date": "2021-12-11 21:47:02 UTC",
      "archived": true,
      "scorecard_score": 3.3,
      "vulnerability_count": 0
    },
    "local_gem": {
      "source_type": "path",
      "version_used": "0.1.0",
      "scorecard_score": null,
      "vulnerability_count": 0
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

| activity | up to date? | OpenSSF | vulns | name                                                         | version used                                                               | latest version                                                             | latest pre-release | last commit                                           | libyear | license |
| -------- | ----------- | ------- | ----- | ------------------------------------------------------------ | -------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------------------ | ----------------------------------------------------- | ------- | ------- |
|          | ✅          | 7.1/10  | ✅    | [async](https://github.com/socketry/async)                   | [2.36.0](https://rubygems.org/gems/async/versions/2.36.0) (2026/01)        | [2.36.0](https://rubygems.org/gems/async/versions/2.36.0) (2026/01)        | ❓                 | [2026/01](https://github.com/socketry/async)          | 0.0y    | MIT     |
| 🚩       | ✅          | 3.6/10  | ✅    | [backbone-rails](https://github.com/aflatter/backbone-rails) | [1.2.3](https://rubygems.org/gems/backbone-rails/versions/1.2.3) (2016/02) | [1.2.3](https://rubygems.org/gems/backbone-rails/versions/1.2.3) (2016/02) | ❓                 | [2016/02](https://github.com/aflatter/backbone-rails) | 0.0y    | MIT     |
| ❓       | ❓          | ❓      | ✅    | local_gem                                                    | 0.1.0 (path)                                                               | ❓                                                                         | ❓                 | ❓                                                    | -       | -       |
| 🚩       | ❓          | 3.3/10  | ✅    | [nested_form](https://github.com/ryanb/nested_form)          | 0.3.2 (git)                                                                | ❓                                                                         | ❓                 | [2021/12](https://github.com/ryanb/nested_form)       | -       | MIT     |

**Ruby 4.0.1** (latest) ✅

**CycloneDX** -- a standards-track SBOM so your dependency graph and still_active's signals flow into Trivy, Dependency-Track, or Snyk:

```bash
still_active --cyclonedx                 # CycloneDX 1.6 to stdout
still_active --cyclonedx=sbom.json       # write to a file
still_active --cyclonedx --cyclonedx-version=1.7
```

Emits **1.6 by default** — the version mainstream consumers ingest today (`cyclonedx-core-java`/Dependency-Track and `cyclonedx-go`/Trivy both cap at 1.6 as of 2026); `--cyclonedx-version=1.7` opts into the latest. Gem name/version/`purl`/licenses and vulnerabilities map to native CycloneDX fields; maintenance signals with no native home (archived, OpenSSF score, libyear, last commit, yanked) ride in `still_active:`-namespaced `properties`. The `serialNumber` is content-derived, so two SBOMs of the same lockfile differ only by their generation timestamp.

### SARIF output (GitHub Code Scanning)

Emit findings as SARIF 2.1.0 — they show up in the GitHub Security tab and as inline annotations on `Gemfile.lock` in pull requests.

> **See it live:** this repo audits itself on every push. Browse the live findings in the [Code Scanning Security tab](https://github.com/SeanLF/still_active/security/code-scanning?query=tool%3Astill_active+is%3Aopen) — currently 2× `SA005` (low OpenSSF Scorecard).

```bash
still_active --sarif                       # writes still_active.sarif.json
still_active --sarif=path/to/out.sarif.json
still_active --sarif=-                     # stdout
```

**Easy mode** — use the [`still_active-action`](https://github.com/SeanLF/still_active-action) wrapper:

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

**Plain bundle exec** if you'd rather pin still_active in your Gemfile:

```yaml
      - run: bundle exec still_active --sarif
        env:
          GITHUB_TOKEN: ${{ github.token }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: still_active.sarif.json }
```

Rule reference (SA001–SA007) and how to suppress: see [`docs/rules.md`](docs/rules.md).

### Baseline diff (PR review)

`--baseline=FILE` compares the current run against a previously captured JSON snapshot and emits a markdown delta report. Designed for the PR question reviewers actually ask: **what got worse?**

```bash
# Locally — capture from main, compare to your branch
git checkout main && still_active --json > /tmp/main.json
git checkout my-branch && still_active --baseline=/tmp/main.json
```

In CI, capture a baseline on main and compare on PR branches. Exits 1 if any regression is detected (new vulns, newly-archived deps, scorecard drops crossing 7.0, libyear growth on unchanged versions, Ruby newly EOL, etc.).

The diff supersedes `--sarif`, `--terminal`, `--markdown`, and `--json` when set.

When a run is detected as Dependabot- or Renovate-authored (via `GITHUB_ACTOR`, a `dependabot/`/`renovate/` branch, or the commit subject), the report leads with a one-line narrative — "Dependabot bump: `rack` 2.0.0 → 2.0.6" — and `--json` gains a top-level `pr_context`. Detection is best-effort and conservative: it never produces a false positive on an ordinary commit, and a miss costs only the narrative line.

### Alongside `dependency-review-action`

GitHub's first-party [`dependency-review-action`](https://github.com/actions/dependency-review-action) runs server-side on PRs and surfaces **vulnerabilities, licenses, and OpenSSF Scorecard** scores from GitHub's dependency-graph diff. It does not surface maintenance signals — last-commit activity, archived repos, libyear, Ruby EOL, or yanked versions — and is GitHub.com / GHES only. `still_active` is the complement, not a replacement:

|                              | `dependency-review-action`         | `still_active`                              |
| ---------------------------- | ---------------------------------- | ------------------------------------------- |
| Platform                     | GitHub.com / GHES only             | Any CI                                      |
| Languages                    | Multi (GitHub dep graph)           | Ruby                                        |
| Vulnerabilities              | GHSA                               | deps.dev + ruby-advisory-db (merged)        |
| Licenses                     | Yes (allow/deny gating)            | Surfaced (no gating)                        |
| OpenSSF Scorecard            | Yes (display)                      | Yes (display + threshold)                   |
| **Last-commit activity**     | -                                  | **Yes**                                     |
| **Archived repo detection**  | -                                  | **Yes**                                     |
| **Libyear drift**            | -                                  | **Yes**                                     |
| **Ruby EOL detection**       | -                                  | **Yes**                                     |
| **Yanked version detection** | -                                  | **Yes**                                     |
| Diff vs base                 | Native (GitHub API)                | `--baseline=FILE`                           |
| Output                       | Inline PR annotations              | Terminal / Markdown / JSON / SARIF / CycloneDX |

Run both: let `dependency-review-action` gate CVEs and licenses, and `still_active` add the maintenance lens on the same PR.

```yaml
on: pull_request

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high
          show-openssf-scorecard: true

  maintenance-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ruby/setup-ruby@v1
        with: { ruby-version: ".ruby-version", bundler-cache: true }
      - uses: SeanLF/still_active-action@v0
        with:
          fail-if-critical: true
```

### CI quality gating

Use exit-code flags to fail CI pipelines based on dependency status:

```bash
# fail on critically stale or archived gems
still_active --fail-if-critical --json

# fail on any stale, critical, or archived gem
still_active --fail-if-warning --json

# fail if any gem has known vulnerabilities
still_active --fail-if-vulnerable --json

# fail only on high/critical severity vulnerabilities
still_active --fail-if-vulnerable=high --json

# fail if any gem is more than 3 libyears behind
still_active --fail-if-outdated=3 --json

# combine flags and exclude known exceptions
still_active --fail-if-warning --fail-if-vulnerable --ignore=legacy_gem --json
```

### Configuration file (`.still_active.yml`)

`--ignore=GEM` is blunt: it drops a gem from **every** gate at once, so accepting one unfixable advisory also blinds you to that gem going archived or to a *new* CVE. A committed `.still_active.yml` in the project root replaces that with granular, auditable suppression, and lets you keep your policy flags in version control instead of threading them through every invocation.

```yaml
# .still_active.yml -- policy defaults plus granular suppression
fail_if_critical: true
fail_if_vulnerable: high       # true, or a minimum severity: low|medium|high|critical
fail_if_outdated: 3            # libyears
unreleased_commits: true
output: json                   # terminal | markdown | json

# Pull bundler-audit's accepted-advisory list instead of maintaining two files
import:
  - .bundler-audit.yml

ignore:
  # Accept ONE advisory, by id -- a different/new CVE on nokogiri still fails
  - advisory: CVE-2024-1234
    gem: nokogiri
    reason: "no fix released; not reachable from our code path"
    expires: 2026-09-01        # re-surfaces as a normal failure after this date

  # Accept staleness on a vendored gem, but still fail if it gets a CVE
  - gem: legacy_thing
    signal: activity            # activity | vulnerability | libyear
    reason: "vendored, intentionally frozen"

  # A bare gem name keeps the old whole-gem behaviour (mutes every signal)
  - some_internal_gem
```

Design:

- **Granularity.** Key by `advisory:` (one CVE) and/or `signal:` (`activity` / `vulnerability` / `libyear`), not the whole gem. A vulnerability suppression **must** name an advisory id, so a newly disclosed CVE on the same gem is never pre-silenced. `--ignore=GEM` (and a bare gem-name entry) still mute everything, by design.
- **Precedence.** CLI flag > env var > config file > default. A CLI flag always wins; `--ignore` unions with the file's suppressions rather than replacing them. Secrets (tokens) and invocation-specific paths (`--gemfile`, `--gems`, `--baseline`, output paths) are intentionally **not** read from the file, so a committed config never carries a credential.
- **Expiry.** An `expires:` date makes accepted risk visible: once it passes, the entry stops applying and the finding fails the gate again (Trivy-style), so a suppression can't rot silently. `reason:` is optional but recommended.
- **bundler-audit, suggested not absorbed.** still_active never silently inherits another tool's ignore list: auto-importing `.bundler-audit.yml` would suppress vulnerabilities you only accepted in bundler-audit's context, with no reason or expiry here. Instead, when `--fail-if-vulnerable` is on and an un-imported `.bundler-audit.yml` is present, it prints a one-line hint suggesting the `import:` line, leaving the opt-in to you.
- **Output.** Suppression changes the **exit code** and marks the finding in **SARIF** as a native `suppressions[]` entry (with your `reason` as the justification, so GitHub Code Scanning renders it dismissed rather than open). The finding still appears in JSON/terminal/markdown output; suppression accepts a risk, it doesn't hide that the risk exists.

### Activity thresholds

Activity is driven by release recency (the latest stable or pre-release date), since a release is what you can actually `bundle update` to. A recent commit does not offset a stale release: the last commit date is shown as context and only stands in when a gem has no releases at all (e.g. git-sourced). Thresholds are calibrated against real RubyGems cadence, where healthy mature gems often go a year or more between releases:

- **ok**: last release within 18 months (configurable with `--safe-range-end`)
- **stale**: last release between 18 months and 3 years ago
- **critical**: last release over 3 years ago (configurable with `--warning-range-end`)

### Alternative gem leads (opt-in)

When a gem is flagged archived or critical, `--alternatives` surfaces up to three maintained gems from the same [Ruby Toolbox](https://www.ruby-toolbox.com) category, ranked by total downloads:

```bash
still_active --gems=paperclip --alternatives
```

```text
↳ leads (Ruby Toolbox): shrine · carrierwave · kt-paperclip (verify fit)
```

These are **leads, not recommendations**: same-category does not mean drop-in replacement, so verify fit before switching. Ruby has no authoritative "use instead" metadata (unlike npm `deprecate`, Go's `// Deprecated:`, or NuGet's alternate-package field), so this is a best-effort heuristic. It is silent when the catalog has no entry for the gem, and the feature never blocks or fails a run. Leads appear in terminal, markdown, JSON, and SARIF output. When the flag is off, terminal output shows a one-line hint on flagged gems that the option exists (other formats stay silent).

### Transitive dependencies

Maintenance signals (stale releases, archived repos, last-commit age, advisories, libyear) cover the **full transitive lockfile graph by default** — an unmaintained gem you ship transitively is real risk even though you never named it, and the CVE tools still_active composes with already enumerate the whole resolved graph. This matches libyear-bundler (transitive by default, `--only-explicit` opts out) and every CVE scanner (bundler-audit, npm/cargo/pip-audit are all full-tree).

When a transitive gem trips a signal, the output names the **direct dependency that pulls it in**: `dependency_path` in JSON, a dimmed `↳ transitive, pulled in by X` line in the terminal, a `(transitive, pulled in by X)` suffix in SARIF messages, and a **Transitive findings** list in markdown. That turns an un-actionable transitive finding into an actionable one: you can't bump a gem you didn't choose, but you can replace or pressure the direct gem that drags it in.

`--alternatives` stays **direct-only** by design — "replace gem X with Y" is incoherent for a gem you never selected. Pass `--direct-only` to audit just your declared dependencies (the pre-1.7 behaviour), which is also much cheaper in API calls.

> **Run on a schedule, not on every commit.** Auditing the full graph means a repo/release/advisory lookup for *every* resolved gem (hundreds, for a real app), and the GitHub signals are rate-limited (60 req/hour unauthenticated, 5000 with a token). Maintenance status changes over days and weeks, not per-commit, so a nightly or weekly job (or `--direct-only` in PR gates) gets you the signal without burning your API budget for nothing. This is why advisory tools like Brakeman ship their check database; still_active's signals are inherently live (a release date or an archived flag can't be vendored), so the answer is cadence, not bundling.

### Unreleased commits (opt-in)

`--unreleased-commits` adds an `unreleased_commits` count to the JSON output: commits on the default branch since the latest release's tag. It catches the case the release-recency signal can't, a gem with a *recent* release but a pile of merged-but-unreleased fixes sitting on top, or conversely one that looks stale but is genuinely *done* (no unreleased work). It is the one maintenance signal no Ruby tool surfaces today; only GitHub's own UI shows it.

It is **opt-in and GitHub-only**: enabling it adds one extra API call per GitHub-hosted gem (the git tag is resolved from the RubyGems version by trying `v1.2.3` then `1.2.3` as the compare base), so mind your rate limit on a large lockfile. Non-GitHub sources report `null` (GitLab has no equivalent scalar; the signal is duck-typed, so a provider either implements it or doesn't). The count is **informational and never gates a run**. Read it as a lead, not a verdict: it is inflated for monorepos (the count spans the whole repository, e.g. `bundler` living in `rubygems/rubygems`) and for release-branch projects (the default branch is the next-version trunk, so `rails` reads ~2000 commits ahead of its latest stable tag).

### Data sources

- **Versions, release dates, and licenses** from [RubyGems.org](https://rubygems.org), [GitHub Packages](https://docs.github.com/en/packages), or [JFrog Artifactory](https://jfrog.com/artifactory/) gem registries
- **Last commit date and archived status** from the [GitHub](https://docs.github.com/en/rest), [GitLab](https://docs.gitlab.com/ee/api/), or [Forgejo/Gitea](https://forgejo.org/docs/latest/user/api-usage/) (Codeberg) API
- **OpenSSF Scorecard**, **vulnerability counts**, and **CVSS severity** from Google's [deps.dev](https://deps.dev) API
- **Additional advisories** from [ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db), merged in when `bundler-audit` is installed alongside (run `bundle audit update` to keep its checkout current)
- **Ruby version freshness** from [endoflife.date](https://endoflife.date)
- **Alternative gem leads** (with `--alternatives`) from the [rubytoolbox/catalog](https://github.com/rubytoolbox/catalog) category data

### Configuration defaults

| Option                  | Default     | Description                                                      |
| ----------------------- | ----------- | ---------------------------------------------------------------- |
| `output_format`         | auto-detect | Coloured terminal on TTY, JSON when piped                        |
| `safe_range_end`        | 1.5 years   | Last release within this range is "ok"                           |
| `warning_range_end`     | 3 years     | Last release within this range is "stale"; beyond is "critical"  |
| `simultaneous_requests` | 10          | Concurrent API requests                                          |

## Development

After checking out the repo, run `bin/setup` to install dependencies and wire git hooks. Then run `rake` to run the full lint + test suite (`rake spec` for just tests, `rake rubocop` for just lint). You can also run `bin/console` for an interactive prompt that will allow you to experiment.

A pre-push hook runs `rake` automatically before each `git push`, so cross-file rubocop rules don't escape to CI. Skip with `git push --no-verify` if you really need to.

To install this gem onto your local machine, run `bundle exec rake install`. New versions are published automatically to [rubygems.org](https://rubygems.org) when a GitHub Release is created (via trusted publishing).

## Contributing

Bug reports and pull requests are welcome.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
