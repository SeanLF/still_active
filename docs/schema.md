# still_active JSON output schema (v1)

`still_active --json` emits a versioned envelope. The schema is stable within a major version; additive changes (new fields) do not bump `schema_version`.

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
| `schema_version` | integer | `1` for this version. Bumped only on breaking changes. |
| `tool.name` | string | Always `"still_active"`. |
| `tool.version` | string | Gem version that produced this report (e.g. `"1.4.0"`). |
| `generated_at` | string | ISO-8601 UTC timestamp (e.g. `"2026-05-22T14:33:00Z"`). |
| `gems` | object | Map of gem name → gem data (see below). |
| `ruby` | object \| absent | Ruby freshness info; absent when not detectable. |

## Per-gem fields

| Field | Type | Notes |
| --- | --- | --- |
| `source_type` | string | `"rubygems"`, `"git"`, `"path"`, or `"unknown"`. |
| `version_used` | string \| nil | The version pinned in `Gemfile.lock`. |
| `latest_version` | string \| nil | Latest non-pre-release version on RubyGems. |
| `latest_version_release_date` | string \| nil | ISO-8601 timestamp. |
| `latest_pre_release_version` | string \| nil | Latest pre-release version if any. |
| `latest_pre_release_version_release_date` | string \| nil | ISO-8601 timestamp. |
| `repository_url` | string \| nil | Canonical GitHub/GitLab URL when found. |
| `last_commit_date` | string \| nil | ISO-8601 timestamp of the latest commit. |
| `archived` | bool \| nil | `true` if the repo is archived; `nil` if unknown. |
| `scorecard_score` | float \| nil | OpenSSF Scorecard score 0.0–10.0 from deps.dev. |
| `vulnerability_count` | integer | Number of advisories affecting `version_used`. |
| `vulnerabilities` | array | One entry per advisory (see below). |
| `ruby_gems_url` | string \| absent | Present for rubygems-sourced gems. |
| `up_to_date` | bool \| absent | Present when `version_used` is known. |
| `version_used_release_date` | string \| nil | ISO-8601 timestamp. |
| `version_yanked` | bool \| absent | `true` if `version_used` has been yanked. |
| `license` | string \| nil | SPDX license identifier(s) for `version_used`, comma-joined when more than one. `nil` when unknown (e.g. git/path sources). |
| `libyear` | float \| nil | Years between `version_used` and `latest_version`. |

### Vulnerability fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Advisory ID (`GHSA-*`, `CVE-*`, etc.). |
| `url` | string \| nil | Canonical advisory URL. |
| `title` | string \| nil | Short title from deps.dev. |
| `aliases` | array | Cross-referenced IDs. |
| `cvss3_score` | float \| nil | CVSS v3 base score (0.0–10.0). |
| `cvss3_vector` | string \| nil | CVSS v3 vector string. |
| `cvss2_score` | float \| nil | CVSS v2 fallback for older advisories. |

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

## Versioning policy

- **Additive changes** (new fields): no schema bump.
- **Renamed / removed fields or semantic changes**: `schema_version` increments.
- Tools consuming this JSON should reject reports where `schema_version` exceeds the major version they understand.
