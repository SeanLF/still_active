# Changelog

## Unreleased

## [0.5.0] - 2023-05-21

- Explicitly test against ruby 3.2
- Remove support for ruby 2.7
- Bump dependencies
- Lint

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
