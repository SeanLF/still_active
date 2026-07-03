# OSV enrichment + "pins below the fix" — design

Status: approved 2026-07-02. Two atomic PRs, each deployable.

## Problem

Two verified gaps, one root cause. Both de-risking studies (2026-07-02) converged:

1. **The security-relevant poison tier over-fires.** `PoisonSecurityCorrelator` gates
   `capped_dep_vulnerable` on `VulnerabilityHelper.severity_at_or_above?(vulns, "high")`,
   which **fails closed** on any advisory with no usable CVSS score. deps.dev (our only
   advisory source) stores only CVSS 3.x and returns `cvss3Score: 0` for CVSS-4-era
   advisories, so in practice *every* corpus hit — protobuf included — fires on an
   unscored advisory, never a genuinely-scored HIGH. The "HIGH" gate filters nothing;
   the tier is largely a dormancy signal wearing a security label.
2. **We can't tell "capped below the fix" from "patchable in place."** The killer claim
   is "the dead cap holds you below the version that *fixes* the CVE." deps.dev carries
   **no fixed-version ranges at all**, so this is currently uncomputable.

Both need the same thing: **OSV** (`api.osv.dev`) is the only source that carries a real
severity label (`database_specific.severity`) *and* per-package fixed ranges
(`affected[].ranges[].events[].fixed`). Verified against the live API docs 2026-07-02.

## Non-goals / deferred (with reasons)

- **OSV as an advisory *discovery* source.** deps.dev already discovers advisories
  (`advisoryKeys`); OSV only *enriches* the ones we know by ID. No merge/dedup churn.
- **`querybatch`.** It returns `{id, modified}` only, not full records — useless when we
  already hold the IDs and need details. Ruled out.
- **CycloneDX severity-only rating.** A label-only OSV advisory (no CVSS number) exports
  no CycloneDX rating today, while SARIF now marks it `error` -- a format inconsistency. A
  severity-only rating (`{ "severity": "high" }`, schema-valid, no fabricated score) would
  close it. Deferred: both reviewers judged the current no-rating behavior correct/honest,
  and it's a separable export-completeness enhancement, not part of the deflation. Small
  follow-up.
- **Bulk `all.zip` aggregator** (`storage.googleapis.com/osv-vulnerabilities/<ECO>/all.zip`).
  Real, no-auth, full records, `modified_id.csv` for incremental — but it's an
  ecosystem-wide dump (tens of MB / thousands of records) to serve a handful of per-tree
  lookups. Right tool at **corpus scale** (the scaled moat study, a future "rotting"
  feature), wrong tool for a single audit. Documented as the scale path, not built now.
- **Any CVSS scoring engine (v3 or v4).** OSV's `database_specific.severity` label is present
  on *every* GHSA-sourced advisory (verified: it reads `HIGH` on both a CVSS-v3 and a
  CVSS-v4 record), so the label is a universal fallback for correct gating and correct SARIF
  level. deps.dev already supplies a real *number* for v3-scored advisories; the only thing
  it misses is v4-only, which the label covers. So **no vector parsing is needed** for the
  deflation. A precise *number* for a v4-only advisory (to sharpen the SARIF security-severity
  display) is the only reason to parse a vector, and that needs the table/MacroVector v4
  algorithm — a real correctness surface; don't hand-roll. Deferred to a scoped follow-up that
  would vendor a *vetted* v4 scorer. See `scratch/cvss_v4_lib_vetting.md` (in-flight).

## Architecture

New provider `lib/still_active/osv_client.rb` (per the "integrations are providers in their
own file" convention; mirrors `DepsDevClient`). Public surface:

```
OsvClient.detail(advisory_id:) -> { severity_label:, cvss_vectors:, affected: [...] } | nil
```

`affected` is filtered to the caller's ecosystem+name at the enrichment site; each carries
its `fixed` versions. A failed/absent OSV lookup returns `nil` and the advisory is left
exactly as deps.dev produced it (degrade to today's behavior, never crash — the fetch is
best-effort enrichment).

Enrichment runs where advisories are already assembled, on **both** paths:
- native: `Workflow#fetch_deps_dev_info` (`workflow.rb`)
- SBOM: `EcosystemLens#vulnerabilities_for` (`ecosystem_lens.rb`)

right after `merge_advisories`. For each advisory, if OSV has detail, attach
`advisory[:osv_severity]` (label) and `advisory[:fixed_versions]` (Array for this
ecosystem+name).

## PR1 — OSV as the severity authority (the deflation)

- `OsvClient` (WebMock-stubbed in specs; bounded concurrency; polite UA; no key needed —
  OSV has no rate limits today).
- Enrich advisories with `osv_severity` + `fixed_versions` on both paths.
- `VulnerabilityHelper` severity layering, in priority order:
  1. real CVSS number — deps.dev `cvss3_score`/`cvss2_score` if positive.
  2. OSV `osv_severity` **label** (`CRITICAL`/`HIGH`/`MODERATE`/`LOW` → `critical`/`high`/
     `medium`/`low`) — drives `highest_severity` / the HIGH+ gate / SARIF *level* only. Does
     NOT fabricate a security-severity number.
  3. neither → unscored → fail-closed (unchanged).
- Effect: SA003 exports real protobuf as `error` not `warning`; the correlator's
  `capped_dep_vulnerable` gate becomes true-HIGH, not fail-closed-on-everything.
- **Honesty rail:** a label-derived level carries no invented CVSS number; the SARIF
  `security-severity` property stays absent (or is marked label-derived), never `7.0`.

## PR2 — "below the fix" ranking (the increment)

- In `PoisonSecurityCorrelator`, for each `capped_dep_vulnerable` constraint: compute the
  lowest OSV `fixed_versions` across the capped dep's HIGH+ advisories and compare against
  the cap's ceiling (max version the `requirement` allows). Reuse `Pep440Helper`
  (`to_gem_requirement_string`) + `VersionHelper#to_gem_version`/`normalize_version` — no
  new comparator.
- Classify: **A** `capped_below_fix` (every fix above the ceiling → genuinely stuck),
  **B** patchable within cap, **C** no fix available.
- **Anchor gotcha:** severity-relevance is judged at the *resolved* version (the correlator
  already reads each dep's tree-version advisories), never the allowed-range floor —
  probing the floor over-counts ~10x (lights up historical Rails CVEs).
- Surface: rank A above B; terminal/markdown/SARIF label
  "unpatchable within cap: <CVE> fixed in <v>, cap allows ≤ <ceiling>". SARIF note→security
  escalation mints a fresh alert (mirrors existing fingerprint dimension).

## Error handling

OSV fetch is best-effort: network error, 404, malformed body, or missing fields → treat as
"no OSV data," advisory unchanged, run continues. A `versions`-only advisory (no `fixed`
event) reads as class C, not a crash. silent-failure-hunter on this path pre-merge — a
failed OSV call must not silently *drop* an advisory deps.dev already found.

## Testing (TDD, RED first)

- `OsvClient` unit: WebMock fixtures — protobuf GHSA with multi-branch fixes, a label-only
  advisory (no CVSS vector), a `versions`-only advisory, a 404, a malformed body.
- `VulnerabilityHelper`: v3-vector parse; label drives level but not number; layering
  priority; fail-closed unchanged.
- `PoisonSecurityCorrelator`: Sentry `<5` → A, Saleor `<7` → B, no-fix → C; resolved-version
  anchoring.
- No live network in any spec.

## Implementation order

1. PR1 red (OsvClient + helper + enrichment specs) → green → review (code-reviewer +
   silent-failure-hunter) → branch → PR → squash auto-merge. NO release.
2. PR2 red → green → review → PR. NO release.
3. Fold the CVSS-v4 vetting verdict in as a scoped follow-up if a safe scorer exists.
