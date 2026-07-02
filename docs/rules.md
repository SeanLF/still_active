# still_active SARIF Rules

Each finding `still_active --sarif` emits maps to one of the rules below. Rule IDs (`SA001`–`SA009`) are stable across versions; renames or removals are breaking changes.

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

**Triggers when:** the gem has had no release for over 3 years and its repository is not archived. For a gem with no releases at all (e.g. git-sourced), the last commit date is used instead. (Release recency drives the signal; a recent commit can't mask a stale release.)

**Why it matters:** dormant gems accumulate latent risk (incompatibilities with new Ruby versions, unpatched edge-case bugs) and, most concretely, a consumer cannot pull fixes that were never released. Not yet a hard fail, but a signal worth tracking.

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

## SA008 — Poison Pill {#sa008}

**Triggers when:** a dormant gem (abandoned or archived) declares a runtime constraint that caps one of its dependencies below that dependency's current latest major.

**Why it matters:** because nobody is shipping the gem, the cap will never lift, and it grows more constraining over time as the capped dependency releases new majors — the tree is held below a ceiling no upstream release will raise. This is the compatibility math across the whole tree a careful dev can't do by hand; the capped dependency is often several levels deep and transitive.

**SARIF level:** `warning` · **security-severity:** none (a maintenance/resolvability finding, not a vulnerability) · **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)

**How to fix:** replace or fork the dormant gem, or vendor a version that relaxes the constraint. For a transitive pill, the finding names the direct dependency that pulls it in — that's the gem you can actually act on.

**When to suppress:** when the cap is deliberate and accepted (e.g. a vendored, intentionally frozen gem). Suppress the `poison` signal for the specific gem in `.still_active.yml`, ideally with an `expires:` date so the acceptance is revisited.

---

## SA009 — Language Runtime Ceiling {#sa009}

**Triggers when:** a resolved package version's declared runtime constraint caps the language runtime you can run: either below every still-supported release (an EOL-forcing cap) or below the latest stable (a latest-not-yet cap). The constraint is the gem's `ruby_version` on the native Ruby path and a package's `requires_python` on the cross-ecosystem (`--sbom`) path. The runtime support window comes from [endoflife.date](https://endoflife.date/) (Ruby and Python calendars).

**Why it matters:** this is the language-runtime sibling of the poison pill. Where a poison pill caps a dependency, this caps your interpreter. An EOL-forcing cap strands you on a runtime that receives no security patches, a genuine upgrade blocker. A latest-not-yet cap is a lower-stakes heads-up: a compatibility ceiling to plan around before you invest, or a place to contribute support for the newest runtime upstream. It is not gated on maintenance status, since the cap is a fact of the resolved version whether or not the package is still shipping.

**Enforcement:** both `ruby_version` (RubyGems/Bundler) and `requires_python` (pip) are *hard install walls*: the resolver refuses an incompatible runtime, so an EOL-forcing cap is a real block, not an inference. still_active reports what the resolver enforces; runtime-correctness beyond that (a native extension that silently breaks) is out of static sight.

**SARIF level:** `note` by default, raised to `error` per result for an EOL-forcing cap · **security-severity:** none (a maintenance/compatibility finding, not a vulnerability) · **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)

**How to fix:** if a newer release of the package lifts the cap, upgrade it (the finding says so when it does, unless a poison-pill on the same package blocks that upgrade). Otherwise replace or fork the package, or contribute support for the newer runtime upstream.

**Reading the negative space:** a declared runtime cap is a maintainer being honest about tested compatibility, not a defect. Equally, **no SA009 findings does not mean "safe to bump your runtime"**: the signal only sees packages that *declare* a cap. The most common real upgrade blockers (native extensions that fail to compile, removed stdlib, deprecated C-API) declare nothing and are invisible here. A latest-not-yet cap is also suppressed for a grace period after a new runtime ships, since "doesn't support it yet" three days in is about the release calendar, not the package.

**When to suppress:** when the pinned version is deliberate and the runtime ceiling is accepted. Suppress the `language_ceiling` signal for the specific package in `.still_active.yml`, ideally with an `expires:` date so the acceptance is revisited.

---

## Stability

- Rule IDs are stable. New rules (SA010+) are additive. Existing rule renames/removals would be breaking changes.
- `partialFingerprints` hash `(rule_id, gem_name, advisory_id?)` — version is **not** included, so a `bundle update` that doesn't change which gems are flagged keeps the same alert IDs (no churn in the GitHub Security UI).
- Rule thresholds (libyear ≥ 1.0, scorecard < 4.0, abandonment ≥ 2 years) are tracked in `lib/helpers/sarif_helper.rb`.
