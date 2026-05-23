# still_active SARIF Rules

Each finding `still_active --sarif` emits maps to one of the rules below. Rule IDs (`SA001`–`SA007`) are stable across versions; renames or removals are breaking changes.

When uploaded via `github/codeql-action/upload-sarif`, findings appear in the GitHub Code Scanning UI and as inline annotations on `Gemfile.lock` in pull requests.

---

## SA001 — Archived Repository {#sa001}

**Triggers when:** the gem's upstream repository (GitHub or GitLab) is marked archived.

**Why it matters:** archived repositories receive no fixes, including security patches. An archived dependency is a known-permanent risk.

**SARIF level:** `error` · **security-severity:** 7.5 · **CWE:** [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) (insufficiently trustworthy component)

**How to fix:**
- Find a maintained fork or alternative gem.
- If you must keep the gem, vendor or fork it so you can apply patches yourself.

**When to suppress:** if the gem is intentionally archived because it's feature-complete and you've audited the attack surface, add it to `--ignore=GEM_NAME` for CI gating. Code Scanning alerts can be dismissed individually in the UI.

---

## SA002 — Abandoned Gem {#sa002}

**Triggers when:** the gem's source repository shows no commit activity for over 2 years, and the repository is not archived.

**Why it matters:** dormant gems accumulate latent risk (incompatibilities with new Ruby versions, unpatched edge-case bugs). Not yet a hard fail, but a signal worth tracking.

**SARIF level:** `warning` · **security-severity:** *(none)* · **tag:** `maintenance`

**How to fix:**
- Verify the gem still works on supported Ruby versions in your CI.
- Look for a maintained alternative.
- If the gem is small, consider vendoring.

**When to suppress:** stable, feature-complete gems (e.g. some parsers, well-defined utilities) legitimately don't need ongoing commits. Add to `--ignore`.

---

## SA003 — Vulnerable Gem {#sa003}

**Triggers when:** deps.dev / OSV reports one or more security advisories affecting the resolved version of the gem — and, when `bundler-audit` is installed with a current advisory checkout, also any advisories `rubysec/ruby-advisory-db` reports for that version. Results from the two sources are merged and deduplicated on shared identifiers (each advisory's `source` is recorded in the JSON output as `deps.dev`, `ruby-advisory-db`, or `merged`).

**Why it matters:** known CVEs against your pinned version are the most actionable signal in the catalog. One SARIF result is emitted per advisory so each can be tracked, dismissed, or remediated independently. The optional ruby-advisory-db source catches Ruby-specific advisories that the rubysec maintainers curate before they propagate to OSV/deps.dev.

**SARIF level:** mapped from CVSS — `error` for ≥ 7.0, `warning` for 4.0–6.9, `note` below 4.0. **security-severity:** per-result, formatted CVSS3 (or CVSS2 fallback). **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) (use of unmaintained third-party components, as a default — advisory-specific CWEs may also apply).

**How to fix:**
- Upgrade to a patched version: `bundle update <gem>`.
- If no patched version exists, evaluate exploit path against your application's exposure.
- Pin to a fixed range once the patch is released.

**When to suppress:** rarely. If the vulnerable code path is provably unreachable in your application, document the analysis and dismiss the Code Scanning alert with a reason.

---

## SA004 — Libyear Behind {#sa004}

**Triggers when:** the gem's libyear (years between resolved version's release and the latest version's release) exceeds 1.0.

**Why it matters:** libyear correlates with painful upgrade work and missed security backports. A gem you've drifted a year behind on takes longer to upgrade safely than one you stay close to.

**SARIF level:** `warning` · **security-severity:** *(none)* · **tag:** `libyear`

**How to fix:** schedule an upgrade. `bundle update <gem>` for the targeted bump, or `bundle outdated --strict` to plan a coordinated sweep.

**When to suppress:** pinning to an older major for genuine compatibility reasons (e.g. waiting for a downstream library to support the new major). Add to `--ignore` and document the reason.

---

## SA005 — Low OpenSSF Scorecard {#sa005}

**Triggers when:** the gem's OpenSSF Scorecard score (from deps.dev) is below 4.0.

**Why it matters:** the Scorecard aggregates supply-chain hygiene signals — branch protection, code review, signed releases, dependency update tools, etc. Low scores indicate weak posture, not active vulnerability, but they correlate with elevated supply-chain risk.

**SARIF level:** `note` · **security-severity:** *(none)* · **tag:** `openssf`

**How to fix:**
- For direct dependencies: weight Scorecard during gem selection; prefer alternatives with stronger posture.
- For transitive dependencies: lobby the direct dependency to improve, or accept the residual risk.

**When to suppress:** common. Scorecard is noisy at low scores (single-commit changes to `.github/` swing scores). Add critical-but-low-Scorecard deps to `--ignore` after manual audit.

---

## SA006 — Ruby EOL {#sa006}

**Triggers when:** the Ruby version in `Gemfile.lock` (or running version, as fallback) has reached end-of-life per [endoflife.date](https://endoflife.date/ruby).

**Why it matters:** EOL Ruby versions receive no further security releases. CVEs disclosed after EOL stay unpatched.

**SARIF level:** `error` · **security-severity:** 8.5 · **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)

**How to fix:** upgrade to a Ruby release branch still receiving patches. The endoflife.date page above shows the active branches.

**When to suppress:** never. If you can't upgrade Ruby immediately, document the plan and target date — but the alert should stay open as a tracking signal.

---

## SA007 — Yanked Version {#sa007}

**Triggers when:** the version pinned in `Gemfile.lock` has been yanked from RubyGems.

**Why it matters:** gems get yanked for serious reasons — security flaws, broken releases, license issues. A yanked pin will fail `bundle install` on fresh checkouts and means you're running code the maintainer chose to recall.

**SARIF level:** `error` · **security-severity:** 8.0 · **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)

**How to fix:** update `Gemfile.lock` to a non-yanked version immediately. `bundle update <gem>` will pick the latest acceptable version.

**When to suppress:** never.

---

## Stability

- Rule IDs are stable. New rules (SA008+) are additive. Existing rule renames/removals would be breaking changes.
- `partialFingerprints` hash `(rule_id, gem_name, advisory_id?)` — version is **not** included, so a `bundle update` that doesn't change which gems are flagged keeps the same alert IDs (no churn in the GitHub Security UI).
- Rule thresholds (libyear ≥ 1.0, scorecard < 4.0, abandonment ≥ 2 years) are tracked in `lib/helpers/sarif_helper.rb`.
