# still_active JSON output schema (v1)

`still_active --json` emits a versioned envelope. The schema is stable within a major version; additive changes (new fields) do not bump `schema_version`.

A machine-readable JSON Schema lives at [`docs/still_active.schema.json`](still_active.schema.json) and is contract-tested against real output; the envelope carries its URL as `$schema` so the output is self-describing.

## Top-level shape

```json
{
  "schema_version": 1,
  "tool": { "name": "still_active", "version": "1.4.0" },
  "generated_at": "2026-05-22T14:33:00Z",
  "gems": {
    "<gem_name>": { ... },
    ...
  },
  "ruby": { ... }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `$schema` | string | URL of the JSON Schema this document conforms to. |
| `schema_version` | integer | `1` for this version. Bumped only on breaking changes. |
| `summary` | object | One-object digest of the audit's posture (see below). |
| `tool.name` | string | Always `"still_active"`. |
| `tool.version` | string | Gem version that produced this report (e.g. `"1.4.0"`). |
| `generated_at` | string | ISO-8601 UTC timestamp (e.g. `"2026-05-22T14:33:00Z"`). |
| `gems` | object | Map of gem name → gem data (see below). |
| `ruby` | object \| absent | Ruby freshness info; absent when not detectable. |
| `pr_context` | object \| absent | Present only when the run is detected as Dependabot/Renovate-authored. `{ "bot": "dependabot" \| "renovate", "bumps": [{ "gem", "from", "to" }] }`. `from` is `null` for Renovate (its commit subject carries no source version); `bumps` is `[]` for grouped/unparseable subjects. Best-effort detection — absence does not guarantee the run is not a bot's. |

## Summary fields

A digest so a consumer reads the headline posture without iterating every gem. Counts derive from the canonical per-gem fields (`activity_level`, `archived`, `up_to_date`, `vulnerability_count`), so they never drift from a separately-thresholded SARIF rule.

| Field | Type | Notes |
| --- | --- | --- |
| `total_gems` | integer | Number of gems audited (direct + transitive). |
| `direct` | integer | Declared dependencies. |
| `transitive` | integer | Pulled-in dependencies (0 with `--direct-only`). |
| `activity` | object | Gem count per `activity_level`: `{ ok, stale, critical, archived, unknown }`. Every key is always present (0 if none). |
| `archived` | integer | Gems whose repo is archived. |
| `up_to_date` | integer | Gems on the latest version (`up_to_date == true`). |
| `outdated` | integer | Gems not on the latest version (`up_to_date == false`). |
| `vulnerable_gems` | integer | Gems with at least one advisory. |
| `vulnerabilities` | integer | Total advisories across all gems. |
| `status` | string | The single worst per-gem `status` (see below), floored at `"vulnerable"` when Ruby is EOL. `"unknown"` only when nothing better is known. The project-level posture in one word. |
| `ruby_eol` | bool \| absent | `true` if the project's Ruby has reached EOL. Absent when Ruby info isn't detectable. |

## Per-gem fields

| Field | Type | Notes |
| --- | --- | --- |
| `source_type` | string | `"rubygems"`, `"git"`, `"path"`, or `"unknown"`. |
| `direct` | bool | `true` for a declared (direct) dependency, `false` for a transitive one. The full transitive graph is audited by default; `--direct-only` restricts to direct deps. |
| `dependency_path` | array \| absent | Present only for transitive gems: the resolved path from a direct dependency down to this gem, e.g. `["rails", "actionpack", "rack"]`. The head is the direct dep a maintainer can actually act on. |
| `version_used` | string \| nil | The version pinned in `Gemfile.lock`. |
| `latest_version` | string \| nil | Latest non-pre-release version on RubyGems. |
| `latest_version_release_date` | string \| nil | ISO-8601 timestamp. |
| `latest_pre_release_version` | string \| nil | Latest pre-release version if any. |
| `latest_pre_release_version_release_date` | string \| nil | ISO-8601 timestamp. |
| `repository_url` | string \| nil | Canonical GitHub/GitLab/Codeberg URL when found. |
| `last_commit_date` | string \| nil | ISO-8601 timestamp of the repository's last activity (GitHub `pushed_at` / GitLab `last_activity_at` / Forgejo `updated_at`), which tracks the latest commit date to the day in practice. |
| `archived` | bool \| nil | `true` if the repo is archived; `nil` if unknown. |
| `activity_level` | string | Derived maintenance verdict: `"ok"`, `"stale"`, `"critical"`, `"archived"`, or `"unknown"`. Driven by release recency, with the last commit used only as a fallback when a gem has no releases. |
| `unreleased_commits` | integer \| null \| absent | Present only with `--unreleased-commits`. Commits on the default branch since the latest release's tag (GitHub-hosted gems only; `null` for non-GitHub sources or when the tag can't be resolved). Informational, never a gate. Inflated for monorepos and release-branch projects (the count covers the whole repo / the next-version trunk), so read it as a lead, not a verdict. |
| `scorecard_score` | float \| nil | OpenSSF Scorecard score 0.0–10.0 from deps.dev. |
| `scorecard_maintained` | float \| nil | OpenSSF Scorecard `Maintained` sub-check 0.0–10.0 (recent commit and issue activity) from deps.dev. `nil` when the project has no scorecard, distinct from `0.0` ("measured: unmaintained"). |
| `status` | string | Single categorical **lifecycle** verdict folding the signals together. Worst-first: `"dead"` (dormant, archived **or deprecated**, and carrying an unpatched advisory -- no one is fixing it, migrate) > `"vulnerable"` (a fixable advisory on an actively-released gem) > `"deprecated"` (the maintainer has said to stop using it; never reported as `"legacy"`, since a deprecation contradicts "done and low risk") > `"archived"` (repo archived) > `"stale"` (drifting, in the warning window) > `"legacy"` (long-dormant but **clean** -- feature-complete, low risk; the "done gem") > `"ok"` (actively maintained) > `"unknown"` (no data, never silently `"ok"`). A display/threshold convenience; the individual fields remain authoritative. |
| `vulnerability_count` | integer | Number of advisories affecting `version_used`. |
| `vulnerabilities` | array | One entry per advisory (see below). |
| `alternatives` | array \| absent | Present only with `--alternatives` on an archived/critical **direct** gem: up to three maintained Ruby Toolbox leads to verify. Direct-only by design (you can't swap a gem you didn't choose). |
| `ruby_gems_url` | string \| absent | Present for rubygems-sourced gems. |
| `up_to_date` | bool \| absent | Present when `version_used` is known. |
| `version_used_release_date` | string \| nil | ISO-8601 timestamp. |
| `version_yanked` | bool \| absent | `true` if `version_used` has been yanked. |
| `license` | string \| nil | SPDX license identifier(s) for `version_used`, comma-joined when more than one. `nil` when unknown (e.g. git/path sources). |
| `deprecated` | bool | `true` when the maintainer has declared the package deprecated in its registry. A stated fact, not inferred from dates, so it is independent of `activity_level`: a package deprecated last month with a release last week is `deprecated` and still recently released. Populated for npm today; registries with no deprecation mechanism (RubyGems, PyPI, Cargo) report `false`, which means "not declared", never "confirmed maintained". |
| `deprecation_reason` | string \| nil | The message the maintainer left with the deprecation, which commonly names the successor (`left-pad`'s reads "use String.prototype.padStart()"). `nil` when they left none. |
| `libyear` | float \| nil | Years between `version_used` and `latest_version`. |
| `poison` | bool \| absent | `true` when a dormant gem caps a dependency below its latest major (a below-latest ceiling). See SA008. |
| `poison_severity` | string \| absent | `note` / `warning` / `critical`, scaling with majors-behind. |
| `poison_security_relevant` | bool \| absent | `true` when a capped dependency is itself known-vulnerable in the tree. |
| `poison_below_fix` | bool \| absent | `true` when the cap holds a vulnerable dependency below its security fix (the strongest poison case). |
| `constraints` | array \| absent | The poison caps: each `{ dependency, requirement, dep_latest, majors_behind, kind }`, plus `capped_dep_vulnerable` / `capped_below_fix` / `below_fix_advisory` / `below_fix_fixed_in` when security-relevant. |
| `language_ceiling` | object \| absent | The runtime (Ruby) EOL ceiling a pinned gem forces. See SA009. |

### Vulnerability fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Advisory ID (`GHSA-*`, `CVE-*`, etc.). |
| `url` | string \| nil | Canonical advisory URL. |
| `title` | string \| nil | Short title from deps.dev. |
| `aliases` | array | Cross-referenced IDs. |
| `cvss3_score` | float \| nil | CVSS v3 base score (0.0–10.0). |
| `cvss3_vector` | string \| nil | CVSS v3 vector string. (Always `nil` for `ruby-advisory-db`-only advisories — bundler-audit exposes no vector.) |
| `cvss2_score` | float \| nil | CVSS v2 fallback for older advisories. |
| `source` | string | Which source reported the advisory: `"deps.dev"`, `"ruby-advisory-db"`, or `"merged"` (both). `ruby-advisory-db` entries appear only when `bundler-audit` is installed with a current advisory checkout. |
| `osv_severity` | string \| nil | OSV/GHSA qualitative label (`HIGH`, etc.), used when deps.dev can't score a CVSS-4-only advisory. |
| `osv_cvss_score` | float \| nil | CVSS base score from OSV enrichment. |
| `cvss_version` | string \| nil | CVSS version of the scored vector (e.g. `3.1`, `4.0`). |
| `cvss_vector` | string \| nil | The scored CVSS vector string. |
| `fixed_versions` | array | Versions that patch the advisory (empty when none is published). |
| `no_fix_available` | bool | `true` when no fixed version exists — you can't upgrade out of it. |

## Ruby fields

| Field | Type | Notes |
| --- | --- | --- |
| `version` | string | Ruby version from `Gemfile.lock` `RUBY VERSION` section, falling back to the running process. |
| `release_date` | string \| nil | ISO-8601 timestamp of the running version's release. |
| `eol_date` | string \| nil | ISO-8601 timestamp of EOL per endoflife.date. |
| `eol` | bool | `true` if the version has reached EOL. |
| `latest_version` | string \| nil | Latest patch version of any active branch. |
| `latest_release_date` | string \| nil | ISO-8601 timestamp. |
| `libyear` | float \| nil | Years between current Ruby release and latest. |

## The supported integration surface

**This JSON envelope is the API.** If you are building on top of still_active, parse this (or the SARIF output, or the CycloneDX output). Those are versioned, contract-tested against real output, and covered by the policy below.

**The Ruby constants under `StillActive::` are internal**, and are not a supported interface even though they are technically public. Concretely, they are not usable as one:

- `StillActive.config` is a process-global mutable singleton read from across the library, so two audits with different settings cannot run in one process, and concurrent use is unsafe.
- `Workflow.call` takes no arguments; it reads its input from that singleton.
- Every threshold decision (`--fail-if-*` and suppression matching) is private to `CLI`, so there is no supported way to ask "is this result a failure under these thresholds" without reimplementing it.
- `CLI#run` calls `exit` directly, so it cannot be embedded.

None of this is an oversight to be worked around; it is what makes the CLI simple. Shell out and parse the output. If you need something the output does not carry, that is worth [an issue](https://github.com/SeanLF/still_active/issues) rather than reaching into the internals, because the internals will change without a `schema_version` bump and the output will not.

## Versioning policy

- **Additive changes** (new fields): no schema bump.
- **Renamed / removed fields or semantic changes**: `schema_version` increments.
- Tools consuming this JSON should reject reports where `schema_version` exceeds the major version they understand.
