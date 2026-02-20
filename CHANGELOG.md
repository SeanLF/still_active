# Changelog

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
