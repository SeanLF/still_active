# Configuration and signal tuning

The [README](../README.md#configuration) shows a `.still_active.yml` starter. This page covers the full semantics, the activity thresholds, and how the transitive, alternatives, and unreleased-commits signals behave.

## `.still_active.yml`

A committed file in the project root keeps policy in version control and provides granular, auditable suppression. It mirrors the policy flags (`fail_if_*`, `output`, `direct_only`, `unreleased_commits`, `alternatives`) plus an `ignore:` block and an optional `import:`.

- **Granularity.** Key an `ignore:` entry by `advisory:` (one CVE) and/or `signal:` (`activity` / `vulnerability` / `libyear` / `poison` / `language_ceiling`), not the whole gem. A vulnerability suppression **must** name an advisory id, so a newly disclosed CVE on the same gem is never pre-silenced. A bare gem name (or `--ignore=GEM`) still mutes every signal, by design.
- **Precedence.** CLI flag > env var > config file > default. A CLI flag always wins; `--ignore` unions with the file's suppressions rather than replacing them. Secrets (tokens) and invocation-specific paths (`--gemfile`, `--gems`, `--baseline`, output paths) are intentionally **not** read from the file, so a committed config never carries a credential.
- **Expiry.** An `expires:` date makes accepted risk visible: once it passes, the entry stops applying and the finding fails the gate again, so a suppression can't rot silently. `reason:` is optional but recommended. A suppression naming a gem that isn't in your dependency graph (a typo, or a gem you've removed) is surfaced as a warning, so dead entries don't accumulate.
- **bundler-audit, suggested not absorbed.** `still_active` never silently inherits another tool's ignore list. When `--fail-if-vulnerable` is on and an un-imported `.bundler-audit.yml` is present, it prints a one-line hint suggesting the `import:` line, leaving the opt-in to you.
- **Output.** Suppression changes the **exit code** and marks the finding in **SARIF** as a native `suppressions[]` entry (with your `reason` as justification, so GitHub Code Scanning renders it dismissed). The finding still appears in JSON/terminal/markdown output; suppression accepts a risk, it doesn't hide that the risk exists.

## Activity thresholds

Activity is driven by release recency (the latest stable or pre-release date), since a release is what you can actually `bundle update` to. A recent commit does not offset a stale release: the last commit date is shown as context and only stands in when a gem has no releases at all (e.g. git-sourced). Thresholds are calibrated against real RubyGems cadence, where healthy mature gems often go a year or more between releases:

- **ok**: last release within 18 months (`--safe-range-end`)
- **stale**: last release between 18 months and 3 years ago
- **critical**: last release over 3 years ago (`--warning-range-end`)

### Configuration defaults

| Option                  | Default     | Description                                                      |
| ----------------------- | ----------- | ---------------------------------------------------------------- |
| `output_format`         | auto-detect | Coloured terminal on TTY, JSON when piped                        |
| `safe_range_end`        | 1.5 years   | Last release within this range is "ok"                           |
| `warning_range_end`     | 3 years     | Last release within this range is "stale"; beyond is "critical"  |
| `simultaneous_requests` | 10          | Concurrent API requests                                          |

## Transitive dependencies

Maintenance signals cover the **full transitive lockfile graph by default**: an unmaintained gem you ship transitively is real risk even though you never named it, and this matches `libyear-bundler` and every CVE scanner (`bundler-audit`, npm/cargo/pip-audit are all full-tree).

When a transitive gem trips a signal, the output names the **direct dependency that pulls it in** (`dependency_path` in JSON, a dimmed `↳ transitive, pulled in by X` line in the terminal, a `(transitive, pulled in by X)` suffix in SARIF, a **Transitive findings** list in markdown). You can't bump a gem you didn't choose, but you can replace or pressure the direct gem that drags it in.

Pass `--direct-only` to audit just your declared dependencies (much cheaper in API calls). `--alternatives` is always direct-only: "replace gem X with Y" is incoherent for a gem you never selected.

## Alternative gem leads (`--alternatives`)

When a gem is flagged archived or critical, `--alternatives` surfaces up to three maintained gems from the same [Ruby Toolbox](https://www.ruby-toolbox.com) category, ranked by total downloads:

```text
↳ leads (Ruby Toolbox): shrine · carrierwave · kt-paperclip (verify fit)
```

These are **leads, not recommendations**: same-category does not mean drop-in replacement. Ruby has no authoritative "use instead" metadata (unlike npm `deprecate`, Go's `// Deprecated:`, or NuGet's alternate-package field), so this is a best-effort heuristic. It is silent when the catalog has no entry, and never blocks or fails a run.

## Unreleased commits (`--unreleased-commits`)

Adds an `unreleased_commits` count to JSON output: commits on the default branch since the latest release's tag. It catches what release-recency can't, a gem with a recent release but a pile of merged-but-unreleased fixes on top, or one that looks stale but is genuinely *done*.

It is **opt-in and GitHub-only** (one extra API call per GitHub-hosted gem), the count is **informational and never gates a run**, and non-GitHub sources report `null`. Read it as a lead: it is inflated for monorepos and release-branch projects (e.g. `rails` reads thousands of commits ahead of its latest stable tag).
