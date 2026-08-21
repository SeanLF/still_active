# still_active SARIF Rules

Each finding `still_active --sarif` emits maps to one of the rules below. Rule IDs (`SA001`–`SA009`) are stable across versions; renames or removals are breaking changes.

When uploaded via `github/codeql-action/upload-sarif`, findings appear in the GitHub Code Scanning UI and as inline annotations on `Gemfile.lock` in pull requests.

---

## SA001 — Archived Repository {#sa001}

**Triggers when:** the gem's upstream repository (GitHub, GitLab, or Forgejo/Gitea) is marked archived.

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

**SARIF level:** mapped from CVSS — `error` for ≥ 7.0, `warning` for 4.0–6.9, `note` below 4.0. An **unscored but confirmed** advisory is elevated to `warning` (never an informational note) and fails *closed* against a severity gate, since a confirmed advisory we can't score could be anything up to critical. Note that deps.dev stores only CVSS 3.x, so a **CVSS-4-only advisory** arrives with a `cvss3Score` of `0`; still_active treats a score of `0` as *unscored* (a real 0.0 never appears on a published advisory), so such an advisory reads as unscored rather than "low" — otherwise a HIGH finding could silently clear a gate or export as informational. **security-severity:** per-result, formatted CVSS3 (or CVSS2 fallback); omitted when unscored. A CVSS-4-only advisory's number is recovered from its v4 vector only when the optional [`cvss-suite`](https://rubygems.org/gems/cvss-suite) gem is installed; the SARIF *level* and the severity gate come from the OSV/GHSA label either way, so the number sharpens display but never changes gating. **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) (use of unmaintained third-party components, as a default — advisory-specific CWEs may also apply).

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

**Security-relevant caps (the strongest case):** when the pinned dependency is *itself* known-vulnerable in the same tree — a HIGH-or-above (or unscored, fail-closed) advisory — the finding is flagged `poison_security_relevant` (and the specific cap `capped_dep_vulnerable`) in the JSON. This is the "a dead dependency is holding you on a known-vulnerable dependency, below the fix" case: a real security finding, not maintenance hygiene. still_active gates on the advisory's *severity*, not its exploitability — reachability is beyond static, metadata-only analysis and out of scope. The correlation is computed whole-tree from data already assembled (no extra fetches).

**SARIF level:** `warning` (by tier), **escalated to `error` when security-relevant** (it pins a known-vulnerable dep). The human/markdown output forces it red, names the pinned vulnerable dependency, and leads with these findings. · **security-severity:** none for a plain cap (a maintenance/resolvability finding, not a vulnerability) · **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)

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

## SA010 — Deprecated Package {#sa010}

**Triggers when:** the maintainer has marked the package deprecated in its registry. Read from the deps.dev version record still_active already fetches for advisories and release dates, so it costs no extra request on either path.

**Why it matters:** every other rule here infers abandonment from evidence: dates, repository state, release cadence. This one does not infer anything. The person who publishes the package has said to stop using it, and the deprecation message usually names the successor (`left-pad`'s reads "use String.prototype.padStart()"). It is the signal the rest of the tool approximates.

It also fires where recency-based tooling is blind by construction. A package deprecated last month with a release last week looks perfectly healthy by dates, so SA010 is deliberately independent of the activity signals rather than a modifier on them.

**Coverage, honestly:** npm is the ecosystem where this is populated today. RubyGems, PyPI and Cargo have no deprecation mechanism to read, so the field is present and `false` for them rather than meaningful. Nothing is inferred to fill that gap: absence of a deprecation is not evidence of maintenance. Any ecosystem deps.dev later populates lights up with no change here.

**Enforcement:** a declaration, not a wall. Nothing stops you installing a deprecated package; npm prints the message on install. still_active reports the declaration, and the `status` verdict treats it as more serious than an archived repository (which can just mean development moved) and less urgent than a live vulnerability.

**SARIF level:** `error` · **security-severity:** 7.5 · **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html)

**How to fix:** read the deprecation message, which usually names the successor, and migrate. There will be no further fixes, including security patches.

**Interaction with `status`:** a deprecated package is never `legacy`. `legacy` means "long-dormant but done, low risk", and a deprecation is the maintainer contradicting exactly that reading. A deprecated package carrying a vulnerability is `dead` even when it is still publishing releases, because waiting for a patch on a package its maintainer has abandoned is not a plan.

**When to suppress:** when the migration is scheduled but not done, or when you have deliberately pinned a deprecated package you vendor yourself. Suppress the `deprecated` signal for the specific package in `.still_active.yml`, ideally with an `expires:` date.

---

---

## Stability

- Rule IDs are stable. New rules (SA010+) are additive. Existing rule renames/removals would be breaking changes.
- `partialFingerprints` hash `(rule_id, gem_name, advisory_id?)` — version is **not** included, so a `bundle update` that doesn't change which gems are flagged keeps the same alert IDs (no churn in the GitHub Security UI).
- Rule thresholds: libyear > 1.0 and scorecard < 4.0 live in `lib/still_active/helpers/sarif_helper.rb`; the abandonment cutoff (release older than 3 years) lives in `lib/still_active/config.rb` (`warning_range_end`).
