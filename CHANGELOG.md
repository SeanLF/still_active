# Changelog

## [Unreleased]

### Added

- JFrog Artifactory gem registry support: fetches versions from `.jfrog.io` RubyGems-compatible registries via the versions API with an AQL search fallback. Auth reuses Bundler's per-source credentials when present, otherwise a global token via `--artifactory-token` or `STILL_ACTIVE_ARTIFACTORY_TOKEN` (requires a matching `--artifactory-host` / `STILL_ACTIVE_ARTIFACTORY_HOST`).

### Fixed

- GitHub Packages version lookups now URL-escape the (lockfile-derived) gem name, matching the Artifactory path. A name with URL-unsafe characters previously raised `URI::InvalidComponentError`, which was swallowed and silently dropped that gem from the audit. Defensive hardening for the untrusted-lockfile stance; the GitHub token is never sent off the fixed `rubygems.pkg.github.com` host. (#50)

## [1.6.0] - 2026-06-08

### Added

- `--alternatives` surfaces up to three maintained alternative gems for any dependency still_active flags as archived or critically abandoned, drawn from the [rubytoolbox/catalog](https://github.com/rubytoolbox/catalog) category data and ranked by total RubyGems downloads. Presented as **leads to verify, not vetted recommendations** — same Ruby Toolbox category does not guarantee a drop-in replacement — reflecting that Ruby has no authoritative successor metadata the way npm (`deprecate`), Go (`// Deprecated:`), or NuGet (alternate-package) do. Opt-in and best-effort: the catalog is fetched once and cached under `XDG_CACHE_HOME` with a 7-day TTL, any fetch/parse failure degrades to silence, and nothing here can block a run or affect `--fail-if-*` exit codes. Leads render in terminal (a dimmed sub-line), markdown (an Alternatives section), JSON (an additive `alternatives` array), and SARIF (appended to the SA001/SA002 result messages); CycloneDX is unchanged. With the flag off, terminal output shows a one-line discoverability hint on flagged gems. Silent when the catalog has no entry for the gem (the common case for niche/long-tail gems). Closes #28.

### Changed

- The `async` runtime dependency now requires `>= 2.2` (previously unconstrained). 2.2.0 is the verified real minimum — earlier 2.x releases hit a fiber-scheduler `io_read` bug under still_active's concurrent fan-out. A new CI job installs every runtime dependency at its declared gemspec floor and runs the suite on the minimum supported Ruby, so an under-set floor now fails loudly instead of silently.

## [1.5.0] - 2026-05-23

### Added

- `--cyclonedx[=PATH]` emits a CycloneDX SBOM (stdout by default, or to a file) so the dependency graph plus still_active's signals flow into Trivy / Dependency-Track / Snyk. Emits **1.6 by default** — the version mainstream consumers ingest today (`cyclonedx-core-java` / Dependency-Track and `cyclonedx-go` / Trivy both cap at 1.6 as of 2026) — with `--cyclonedx-version=1.7` to opt into the latest. Gem name/version/purl/licenses map to native fields; maintenance signals (archived, OpenSSF score, libyear, last commit, yanked) ride in `still_active:`-namespaced `properties`; vulnerabilities map to the top-level `vulnerabilities[]`. The `serialNumber` is content-derived (two SBOMs of the same lockfile are byte-identical apart from the generation timestamp), so SBOMs diff cleanly.
- Dependabot/Renovate awareness: when a run is detected as bot-authored (primarily via the PR author in the GitHub event payload — `pull_request.user.login`, the same authoritative signal `dependabot/fetch-metadata` uses, which unlike `GITHUB_ACTOR` survives a human re-running the workflow — falling back to `GITHUB_ACTOR`, a `dependabot/`/`renovate/` branch, or the commit subject including Dependabot's default unprefixed `Bump X from Y to Z`), output leads with a narrative header (markdown/terminal/baseline-diff: "Dependabot bump: rack 2.0.0 → 2.0.6") and JSON gains a top-level additive `pr_context` (`{ bot, bumps: [{ gem, from, to }] }`). Bump extraction tolerates any configured `commit-message.prefix`/scope (`chore(deps):`, `deps:`, …) once the bot is confirmed, while detection stays conservative to avoid false positives on human commits. Best-effort: false negatives lose only the narrative, never a finding; SARIF is unaffected. See `docs/schema.md`.
- A warning is emitted when mutually-exclusive output flags are combined (`--baseline`/`--sarif`/`--cyclonedx`), naming which one wins, and when `--cyclonedx-version` is set without `--cyclonedx`.
- Dual-source vulnerability data: when `bundler-audit` is installed (with a current `bundle audit update` checkout), still_active reads the `rubysec/ruby-advisory-db` advisories through bundler-audit's own loader and merges them with deps.dev results, deduplicating on shared identifiers. Each advisory carries a `source` field (`deps.dev`, `ruby-advisory-db`, or `merged`); deps.dev is preferred for CVSS/title/vector and ruby-advisory-db fills gaps. Opt-in by composition — no second source unless `bundler-audit` is present; falls back silently to deps.dev only otherwise (with a one-line hint to run `bundle audit update`). Closes the "why do bundler-audit and still_active disagree?" gap. See `docs/schema.md` and `docs/rules.md` (SA003).
- Gem license surfaced from the RubyGems versions payload we already fetch (no extra request). Shows as a `License` column in terminal and markdown output and as an additive `license` field (SPDX identifier, comma-joined when a gem declares more than one) on the JSON per-gem record. `nil`/`-` for git/path sources where no RubyGems metadata exists. See `docs/schema.md`. Read-only metadata only — license *policy* (allow/deny gating) stays the domain of `license_finder`.

## [1.4.2] - 2026-05-22

### Fixed

- Replaced an opaque `NoMethodError` on `nil.specs` with `StillActive::MissingLockfileError` and a clear "run `bundle lock` first" message when a Gemfile exists but no `Gemfile.lock` is reachable. Caught during the still_active-action self-test wiring.

## [1.4.1] - 2026-05-22

### Fixed

- `still_active --gems=X` (or any invocation that doesn't need a Gemfile) crashed with `Bundler::GemfileNotFound` when run from a directory without a Gemfile in the tree. `Config#initialize` eagerly called `Bundler.default_gemfile`. Now `gemfile_path` resolves lazily on first read and falls back to `./Gemfile` when none is reachable.

## [1.4.0] - 2026-05-22

### Added

- `--sarif[=PATH]` emits SARIF 2.1.0 for GitHub Code Scanning. Findings appear in the Security tab and as inline annotations on `Gemfile.lock` in pull requests. Default path: `still_active.sarif.json` (pair with `github/codeql-action/upload-sarif@v3`). `--sarif=-` writes to stdout. Rule reference (SA001–SA007) in `docs/rules.md`. Stable `partialFingerprints` (rule + gem + advisory) keep alert IDs constant across `bundle update`s.
- `--baseline=FILE` compares the current run against a baseline still_active JSON snapshot and emits a markdown delta report. Designed for PR review: surfaces regressions (new vulns, newly-archived deps, scorecard drops crossing OSSF's 7.0 threshold, libyear growth on unchanged versions, Ruby newly EOL). Exits 1 if any regression is detected, 2 on a malformed or unsupported baseline.
- GitHub token cascade: discovers token from `--github-oauth-token`, `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token` in that order. GitLab cascade mirrors it (`--gitlab-token`, `GITLAB_TOKEN`, `glab auth status --hostname=gitlab.com --show-token`). Eliminates the "why am I rate limited?" friction on local runs when `gh`/`glab` are already authed.
- JSON output gains `schema_version`, `tool`, and `generated_at` keys on top of the existing `{gems, ruby}` envelope (shipped since 1.1). Purely additive — existing consumers reading `payload["gems"][name]` continue to work. See `docs/schema.md`.

## [1.3.0] - 2026-04-08

### Changed

- **BREAKING:** Bump minimum Ruby version to 3.3 (3.2 is EOL); transitive dependencies (e.g. `io-event`) now require Ruby >= 3.3

## [1.2.1] - 2026-02-20

### Fixed

- Ruby version freshness reported the running Ruby (e.g. 4.0.1) instead of the target project's Ruby from `Gemfile.lock`; now reads `RUBY VERSION` section from lockfile, falls back to running version only when absent
- Platform-specific gems (e.g. `nokogiri` on multiple architectures) were processed once per platform, wasting API calls and inflating the progress counter total

## [1.2.0] - 2026-02-20

### Added

- `--fail-if-vulnerable[=SEVERITY]` flag: exit 1 if any gem has known vulnerabilities, optionally filtered by severity (low/medium/high/critical)
- `--fail-if-outdated=LIBYEARS` flag: exit 1 if any gem exceeds the given libyear threshold
- Coloured OpenSSF column in terminal output: green for strong practices (7.0+), yellow for notably weak (below 4.0)

### Changed

- Removed composite health score (0-100) and Health column from terminal, markdown, and JSON output; individual columns (vulns, OpenSSF, activity, version) communicate these signals without collapsing them into one number
- Replaced `--fail-below-score` with `--fail-if-vulnerable` and `--fail-if-outdated` for targeted CI gating

### Fixed

- Repository URLs with `.git` suffix (e.g. `socketry/async.git`) caused 404s against GitHub/GitLab APIs
- GitLab 301 redirects for renamed projects silently failed; now follows up to 3 redirects with trusted host check
- Network errors (`ECONNRESET`, timeouts, etc.) during RubyGems version lookup or HTTP API calls dropped the entire gem from results instead of warning
- GitHub Packages URI check used substring match, allowing crafted URLs to bypass host validation; now parses URI and compares host exactly
- Tri-state `archived?` predicate renamed to `archived` to honestly reflect `true`/`false`/`nil` return contract
- Rubocop offences from code scanning (WordArray, IfInsideElse, MultilineHash, frozen_string_literal)

## [1.1.0] - 2026-02-20

### Added

- `--ignore=GEM,GEM2,...` flag to exclude gems from pass/fail checks while keeping them in output
- `--fail-below-score=SCORE` flag for health-based CI gating (exit 1 if any gem scores below threshold)
- Yanked version detection: flags pinned versions that have been pulled from RubyGems
- Archived repo detection via GitHub and GitLab APIs, treated as critical for exit checks
- Libyear metric: years between installed and latest release per gem, total in summary
- Advisory enrichment: CVSS scores, titles, and IDs from deps.dev per vulnerability
- Composite health score (0-100) combining version freshness, activity, OpenSSF Scorecard, and vulnerabilities
- Health column in terminal and markdown output, system average in terminal summary
- Ruby version freshness: reports current Ruby version, EOL status, and libyear behind latest via endoflife.date API
- Source detection: identifies gem source type (rubygems, git, path) from Bundler lockfile
- Non-rubygems gem handling: git/path-sourced gems show gracefully with source indicator instead of failing silently
- GitHub Packages registry support: fetches versions from `rubygems.pkg.github.com` using existing `--github-oauth-token` (requires `read:packages` scope)
- CVSS v2 fallback: older advisories without v3 scores now show severity using v2 scores from deps.dev

### Changed

- Vulnerability column shows count with highest severity label (e.g. "3 (critical)")
- Markdown vulnerability column shows advisory IDs
- Markdown table adds libyear and health columns
- Terminal summary includes libyear total and health average
- JSON output wrapped in `{ "gems": ..., "ruby": ... }` structure
- Version string validation guards against malformed versions from git-sourced gems
- Progress counter on stderr during gem checking so large Gemfiles don't appear frozen
- Actionable rate limit message when GitHub API quota is exhausted
- `--fail-below-score` now validates range (0-100) at parse time
- `--gems` option stores structured data from the start instead of mutating mid-run
- API failures (timeouts, HTTP errors, malformed responses) now warn on stderr instead of degrading silently
- Vulnerability count based on successfully fetched advisories so count and severity always agree

### Fixed

- Vulnerability counts now checked against installed version, not latest (was masking CVEs in older pinned versions)
- `GitlabClient.archived?` returned `false` on API failure instead of `nil`, incorrectly asserting repos were not archived
- `repo_archived?` rescued all `StandardError`, masking bugs; now catches only `Octokit::Error` and `Faraday::Error`
- `last_commit_date` had no error handling; any failure dropped the entire gem from results
- Malformed date strings from GitHub/GitLab APIs no longer raise unhandled `ArgumentError`

## [1.0.2] - 2026-02-19

### Changed

- Reduce gem package from 2.4MB to essentials only (lib/, bin/still_active, LICENSE, README, CHANGELOG, gemspec)

## [1.0.1] - 2026-02-19

### Changed

- Rewrite gemspec summary and description for discoverability (mentions dependency health, outdated, vulnerabilities, abandoned gems)
- Restructure README: problem-first opening, terminal output example, comparison table vs bundle outdated/bundler-audit/libyear-bundler, quick start guide
- Add 13 GitHub topics for search visibility
- Update GitHub repo description

## [1.0.0] - 2026-02-19

### Added

- `--fail-if-critical` and `--fail-if-warning` flags for CI quality gating
- deps.dev integration: OpenSSF Scorecard scores and known CVEs in output
- Autopublish to RubyGems via GitHub Releases (trusted publishing)
- Coloured terminal table as default output format with summary line
- Auto-detection: terminal output for TTY, JSON when piped
- GitLab repository support with `--gitlab-token` flag
- Default token loading from `GITHUB_TOKEN` and `GITLAB_TOKEN` env vars
- Dependabot for bundler and GitHub Actions (grouped minor/patch updates)
- Require MFA for RubyGems publishing

### Changed

- **BREAKING:** Rename `--no-warning-range-end` to `--safe-range-end` (fixes OptionParser conflict)
- **BREAKING:** Default output is now auto-detected (terminal on TTY, JSON when piped); `--markdown` is an explicit opt-in
- **BREAKING:** Markdown table collapsed from 12 to 9 columns (dates inlined with versions)
- Replace `activesupport` with lightweight `CoreExt` refinement
- Remove unused `async-http` dependency (82 -> 66 installed gems)
- **BREAKING:** Bump minimum Ruby version to 3.2 (3.1 is EOL)
- Rename "Scorecard" column to "OpenSSF" for clarity
- Extract shared HTTP helper from DepsDevClient and GitlabClient
- Consolidate VCR test configuration into spec_helper
- Re-record VCR cassettes against live APIs

### Fixed

- Markdown output showed wrong emoji for pre-release version comparison
- Errors during gem lookup now go to stderr instead of corrupting structured output
- Repository URL matching handles dots in org/repo names
- Guard against nil URLs in Repository.valid?
- Handle malformed JSON responses from APIs gracefully
- Terminal output no longer crashes on empty results
- Version comparison uses `Gem::Version` instead of string equality
- deps.dev project ID parsing handles URLs with trailing paths
- Add `faraday-retry` runtime dependency to silence Faraday v2 warning
- Add missing `require "time"` for `Time.parse` in VersionHelper
- Fix `:last_activity_warning_emoji` key typo
- Remove dead `Gemfile` module and unused `include VersionHelper`

## [0.6.0] - 2026-02-19

- Replace `github_api` (unmaintained since 2019) with `octokit`
- Remove `dead_end` dependency (absorbed into Ruby 3.2+ as `syntax_suggest`)
- Bump minimum Ruby version to 3.1
- Test against Ruby 3.1, 3.2, 3.3, 3.4, 4.0, and head
- Bump all dependencies
- Update GitHub Actions to v4/v3
- Migrate rubocop config from `require` to `plugins`

## [0.5.0] - 2023-05-21

- Explicitly test against ruby 3.2
- Remove support for ruby 2.7, truffleruby
- Bump dependencies
- Lint
- Migrate references from master to main

## [0.4.1] - 2022-01-01

- Explicitly test against ruby 3.1
- Fix for using ActiveSupport 7
- schedule running CI once per month

## [0.4.0] - 2021-11-11

- Change minimum version of Ruby to 2.7

## [0.3.0] - 2021-11-11

- Change `safe_range_end` to `no_warning_range_end`
- Fixes for Ruby 2.6 and 2.7

## [0.2.0] - 2021-11-11

- Add `simultaneous-requests` command line parameter (and config option) to specify the maximum number of simultaneous requests

## [0.1.1] - 2021-11-06

- Remove `safe_range_start` command line parameter
- Remove `warning_range_start` command line parameter

- Fix bugs
  - use `last_commit_date` rather than `version_used_release_date` to determine the inactive gem emoji
  - use configured values when determining which emoji to output for the inactive gem emoji
  - use configured values when determining which emoji to output for the using latest version emoji
  - the values for `using_latest_version_emoji` and `inactive_repository_emoji` were reversed in the markdown output
  - `NoMethodError` could be raised `VersionHelper#find_version` when versions was nil

## [0.1.0] - 2021-11-06

- Initial release
