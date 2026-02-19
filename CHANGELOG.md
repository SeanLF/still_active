# Changelog

## Unreleased

### Added

- GitLab repository support with `--gitlab-token` flag

## [1.0.0] - 2026-02-19

### Added

- `--fail-if-critical` and `--fail-if-warning` flags for CI quality gating
- deps.dev integration: OpenSSF Scorecard scores and known CVEs in output
- Autopublish to RubyGems via GitHub Releases (trusted publishing)
- Coloured terminal table as default output format with summary line
- Auto-detection: terminal output for TTY, JSON when piped

### Changed

- Markdown output collapsed from 12 to 9 columns (dates inlined with versions)
- `--markdown` is now an explicit opt-in (was the default)
- Replace `activesupport` with lightweight `CoreExt` refinement
- Remove unused `async-http` dependency (82 -> 66 installed gems)
- Re-record VCR cassettes against live APIs

### Fixed

- Version comparison uses `Gem::Version` instead of string equality (versions ahead of published no longer appear outdated)
- deps.dev project ID parsing handles URLs with trailing paths
- Add `faraday-retry` runtime dependency to silence Faraday v2 warning
- Clean up code smells across helpers and workflow

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
