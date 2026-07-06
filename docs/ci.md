# CI integration

The quickest path is the [`still_active-action`](https://github.com/SeanLF/still_active-action) (see the [README](../README.md#github-action--ci)). This page covers the details: SARIF, running without the action, composing with GitHub's `dependency-review-action`, and cadence.

## SARIF (GitHub Code Scanning)

`--sarif` emits SARIF 2.1.0. Uploaded via `github/codeql-action/upload-sarif`, findings appear in the Security tab and as inline annotations on `Gemfile.lock` in pull requests.

```bash
still_active --sarif                        # writes still_active.sarif.json
still_active --sarif=path/to/out.sarif.json
still_active --sarif=-                      # stdout
```

The finding catalog and how to suppress individual results is in [rules.md](rules.md).

## Without the action

If you'd rather pin `still_active` in your `Gemfile`, run it directly:

```yaml
      - run: bundle exec still_active --sarif
        env:
          GITHUB_TOKEN: ${{ github.token }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: still_active.sarif.json }
```

## Alongside `dependency-review-action`

GitHub's first-party [`dependency-review-action`](https://github.com/actions/dependency-review-action) runs server-side on PRs and surfaces **vulnerabilities, licenses, and OpenSSF Scorecard** scores from GitHub's dependency-graph diff. It does not surface maintenance signals (last-commit activity, archived repos, libyear, Ruby EOL, yanked versions), and is GitHub.com / GHES only. `still_active` is the complement, not a replacement:

|                              | `dependency-review-action`         | `still_active`                              |
| ---------------------------- | ---------------------------------- | ------------------------------------------- |
| Platform                     | GitHub.com / GHES only             | Any CI                                      |
| Languages                    | Multi (GitHub dep graph)           | Ruby native, others via `--sbom`            |
| Vulnerabilities              | GHSA                               | deps.dev + OSV + ruby-advisory-db (merged)  |
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

## Run on a schedule, not on every commit

Auditing the full graph means a repo/release/advisory lookup for *every* resolved dependency (hundreds, for a real app), and the GitHub signals are rate-limited. Maintenance status changes over days and weeks, not per-commit, so a nightly or weekly job (or `--direct-only` in PR gates) gets you the signal without burning your API budget. `still_active`'s signals are inherently live (a release date or an archived flag can't be vendored), so the answer is cadence, not a bundled database.
