# Changelog

## [Unreleased]

### Upgrading to 3.0

3.0 is a major bump because a handful of changes can flip a `--fail-if-*` outcome or an exit code on upgrade. The JSON `schema_version` stays `1` (every output change is additive, apart from `up_to_date` widening from `boolean` to `boolean | null`), and no CLI flag was removed or renamed, but review these before upgrading a pipeline:

- **`--fail-if-vulnerable=<severity>` now fails CLOSED on an unscored advisory** (and bare `--fail-if-vulnerable` now fires on advisories a failed deps.dev fetch used to silently drop). A previously-green run can go red. Review the named advisory (a per-gem stderr note explains why), then fix it or accept it in `.still_active.yml`. Installing the optional `cvss-suite` gem lets a CVSS-4-only advisory get a real score and clear the gate when it's below threshold.
- **Bad CLI input now exits 2** with a friendly `error:` line instead of a Ruby backtrace (previously exit 1). SBOM read/parse errors also exit 2. Wrapper scripts that branch on exit codes should treat 2 as "bad invocation".
- **Two new REQUIRED runtime dependencies**: `semantic_range` (npm/cargo version matching for the below-the-fix signal) and `packageurl-ruby` (SBOM PURL parsing). Both resolve automatically on `gem install`; the Ruby floor is unchanged. `cvss-suite` is deliberately NOT a hard dependency (it exact-pins bundler and caps bigdecimal, the poison-pill pattern still_active itself flags), so install it yourself to light up CVSS-4 scoring.
- **New SARIF rules SA008 (poison-pill) and SA009 (runtime ceiling)** appear automatically in the GitHub Security tab for `--sarif` users, and an unscored advisory now maps to `warning` (was `note`), so a code-scanning policy set to fail on `warning` can newly fire. Rule IDs SA001-SA007 are unchanged.
- **Tokenless runs now resolve GitHub repo signals via ecosyste.ms** instead of hitting the 60/hour API wall and degrading to `unknown`. A tokenless user with `--fail-if-critical`/`--fail-if-warning` may see gems that were silently `unknown` now resolve to a real `stale`/`critical`/`archived` and trip the activity gate. Tokened runs are unaffected.
- **New outbound hosts**: `api.osv.dev` (advisory enrichment) and `endoflife.date` (the runtime-ceiling support window) on the native path, plus `*.ecosyste.ms` for tokenless audits. Egress-restricted CI should allowlist these; each degrades to best-effort (no crash) if blocked.
- **Re-capture your `--baseline` JSON** after upgrading: the new signals and fields show as changes on the first run.

- **New SARIF rule SA010 (deprecated package) and a new `status` value `"deprecated"`.** SA010 is emitted at `error` with security-severity 7.5, so a code-scanning policy that fails on `error` can newly fire on a package whose maintainer has deprecated it. Exit codes are unaffected: the `--fail-if-*` gates read activity, vulnerability, libyear, poison and language-ceiling, not `status`, so no previously-green `still_active` run turns red on this alone. The new **`--fail-if-deprecated`** gate defaults to **off**, like the other opt-in gates, so it cannot break an existing pipeline unless you ask for it. A consumer that switches exhaustively on `status` must handle `"deprecated"`; `schema_version` stays `1`, as this is an added enum value rather than a renamed or removed field.

The new `--fail-if-poison[=TIER]` and `--fail-if-language-ceiling[=TIER]` gates default to **off**, so they never break an existing pipeline unless you opt in.

### Added

- **`--sbom --cyclonedx` emits an enriched SBOM instead of erroring.** SBOM in, SBOM out: the input annotated with the maintenance signals it had no way to carry, so a cross-ecosystem audit can feed Dependency-Track (or anything else that ingests CycloneDX) rather than only being read by a human. This previously errored on the grounds that SBOM-in/SBOM-out would need per-ecosystem PURL reconstruction. It turned out to need none: the input already carries the authoritative PURL, so each component re-emits the one it arrived with, and a consumer matches our output exactly as it matched the input. That is what keeps maven's `group/artifact` and Go's module paths correct, the two shapes hand-rolled reconstruction gets subtly wrong. Each component carries `still_active:`-namespaced properties for the folded `status` verdict, the raw `activity_level` behind it, archived, deprecated (with the maintainer's message), scorecard, libyear, last commit, ecosystem and direct-vs-transitive, plus the advisories as CycloneDX `vulnerabilities`. Output is validated against the official CycloneDX 1.6 schema in the test suite, the same way the SARIF output is. `--sbom --baseline` still errors, since a maintenance-regression diff genuinely needs a snapshot shape a cross-ecosystem SBOM cannot supply. Output-mode precedence on the `--sbom` path is the same as on the native path (`--baseline` > `--sarif` > `--cyclonedx`), so the same two flags never mean different things depending on whether the input was a Gemfile or an SBOM, and setting more than one now warns which mode it is using and which it is ignoring on both paths rather than only the native one.
  The native `--cyclonedx` output gains the same `still_active:status`, `still_active:activity_level` and `still_active:deprecated` properties, which is additive: existing properties are unchanged. `status` and `activity_level` deliberately disagree in the interesting cases: a deprecated package still shipping releases is `status: deprecated` with `activity_level: ok`, so a consumer thresholding on recency reads the second and a consumer asking what to do reads the first.

- **Maintainer-declared deprecation (SA010).** Every other signal in still_active infers abandonment from evidence: release dates, repository state, cadence. This one infers nothing. The person who publishes the package has marked it deprecated in its registry, and the message they left usually names the successor (`left-pad`'s reads "use String.prototype.padStart()"). It is the fact the rest of the tool approximates. It also fires where recency-based tooling is blind by construction: a package deprecated last month with a release last week looks perfectly healthy by dates, so this is deliberately independent of the activity signals rather than a modifier on them. Read from the deps.dev version record still_active already fetches for advisories and release dates, so it costs no extra request, no new host and no new dependency, and it lands on **both** paths at once because the native Ruby audit calls the same endpoint. Surfaced as `deprecated` and `deprecation_reason` in JSON, as a red sub-line in the terminal, as its own markdown section, and as SARIF rule **SA010** (`error`, security-severity 7.5) so it reaches GitHub Code Scanning. Suppressible per package via the `deprecated` signal in `.still_active.yml`, and enforceable in CI with **`--fail-if-deprecated`**, a boolean gate with no tier (a deprecation is not scored: the maintainer either declared it or did not). It is the only gate that can fire on a package every date-based signal reads as healthy, which is why it is its own flag rather than part of `--fail-if-critical`. Off by default, like the other opt-in gates, so it cannot break an existing pipeline.
  Coverage, stated plainly: **npm** is where this is populated today. RubyGems, PyPI and Cargo have no deprecation mechanism to read, so the field is present and `false` for them, meaning "not declared", never "confirmed maintained". Nothing is inferred to fill that gap, and any ecosystem deps.dev later populates lights up with no code change.
  The `status` verdict gains a **`deprecated`** level, ranked above `archived` (a repo can be archived just because development moved) and below `vulnerable`. Two consequences worth knowing: a deprecated package is never reported as `legacy`, because `legacy` means "long-dormant but done, low risk" and a deprecation is the maintainer contradicting exactly that reading; and a deprecated package carrying a vulnerability is `dead` even while still publishing releases, because waiting for a patch on a package its maintainer has abandoned is not a plan.


- **Direct private gem sources are now audited, not skipped.** A gem resolving from a private host still_active has no bespoke client for (a direct Contribsys, Gemstash, Gemfury, or a private mirror) previously reported no version data at all. still_active now reads such a source through the RubyGems compact index (`/info/<gem>`, the protocol every Bundler-compatible host serves, which is how `bundle install` resolves from it), so these gems get real version/latest/libyear signals for the first time, falling back to the same "unqueryable" notice only when a host genuinely doesn't serve it. Credentials come from Bundler's own host-keyed store (`bundle config` / `BUNDLE_<HOST>`), so a source URL from a lockfile only ever receives the credential the user configured for that exact host, and still_active's ambient `--artifactory-token` is never sent to a lockfile-derived host (it stays behind its explicit `--artifactory-host` allowlist). The #43 guard is unchanged: a private gem still never borrows a public name-collision's repository or maintenance data.
- **Poison-pill / compatibility-ceiling signal (SA008).** A dormant or archived package that caps one of its runtime dependencies below that dependency's current latest major holds the tree below a ceiling no upstream release will raise, and it grows more constraining over time as the capped dep ships new majors. still_active flags it with a receipt naming the capped dep, the cap, and how many majors behind it holds you, ranked by a severity tier (`note`/`warning`/`critical`, scaling with majors-behind) and enforceable in CI with `--fail-if-poison[=TIER]`. Rendered in terminal, markdown, and SARIF, and computed for `rubygems` (native) and the flat-resolution SBOM ecosystems. Scoped to flat resolution deliberately: npm nests versions and cargo coexists majors, so a below-latest cap there is subtree-local noise, not a tree-wide block, and is suppressed.
- **Security "below the fix", the strongest poison case, now cross-ecosystem.** When a dormant/archived package pins a dependency that is *itself* known-vulnerable in the same tree, below the version that patches a HIGH-or-critical advisory, you cannot patch the CVE without replacing the dead capper. still_active leads with these findings (red in terminal/markdown, escalated to `error` in SARIF) and names the advisory and its nearest fix. This case travels to **npm and cargo** at patch precision (their fixes are mostly same-major patch bumps, invisible to a major-level check), via a real node-semver/Cargo matcher and a tree-copy soundness guard that only fires when every resolved copy the constraint governs is vulnerable (a safe copy elsewhere, or a patched copy the cap can reach, clears it). The correlation is whole-tree from data already assembled, no extra fetches.
- **Language-runtime ceiling signal (SA009), poison's sibling.** A pinned dependency version can strand you on an end-of-life language runtime (its `required_ruby_version` / `requires_python` forbids a supported one). still_active flags it against the runtime's EOL schedule (from endoflife.date), enforceable with `--fail-if-language-ceiling[=TIER]`, and reconciled against poison so an "upgrade to lift the ceiling" can't contradict a cap that forbids that upgrade. Ruby on the native path; **Python** (`requires_python`) and **.NET/NuGet** on the `--sbom` path. .NET is shaped differently: a package declares a SET of target frameworks, and consuming one is a restore-time wall (NU1202), so the ceiling fires only when every concrete runtime target is end-of-life. A `netstandard` target is the escape hatch (consumable from a current .NET), so its presence never fires, keeping the signal off nearly every modern library; `.NET Framework` (4.x) and `.NET` (Core/5+) are checked against their separate EOL calendars.
- **CVSS-4-only advisory scoring via an optional `cvss-suite`.** deps.dev stores only CVSS 3.x, so a CVSS-4-only advisory arrives unscored; still_active enriches every advisory with OSV's real severity label and fixed-version ranges, and, when the optional `cvss-suite` gem is installed, computes the CVSS-4 base score from the OSV vector. Without it, the OSV/GHSA label still gates and only the computed number is skipped, so the fail-closed logic never reads a real HIGH as clean. `cvss-suite` is opt-in (see Upgrading).
- **Vulnerabilities with no fixed version available are flagged** (`no_fix_available`): a known advisory you cannot upgrade out of, the one you most need to see because upgrading isn't the answer.
- **A schema canary for the deps.dev advisory field** (`api.deps.dev`'s alpha `advisoryKeys`): every cross-ecosystem vulnerability count flows through it, so a silent field rename would zero every count and read a vulnerable package as clean. A known-vulnerable canary (`django 3.0.0`) is checked each run; an empty result warns loudly rather than presenting a possibly-understated "all clear".
- **Direct-vs-transitive on the `--sbom` path, and `--direct-only` now works there.** A cross-ecosystem audit read every package the same way, whether you chose it or it arrived six levels down, which is most of what decides whether a finding is actionable. CycloneDX carries a `dependencies` graph and still_active only ever read `components`, so the answer was sitting unread in the input file. Each package now carries `direct`, and a transitive one carries `dependency_path` naming the declared dependency that pulls it in, head first, the same contract the native Ruby audit has. Terminal and markdown already rendered those fields, so a transitive finding now reads "pulled in by npm/express" cross-ecosystem. `--direct-only` previously parsed on the `--sbom` path and then changed nothing; it now narrows the audit for real, and says how many packages it excluded because the graph could not place them rather than quietly shrinking the scope.
  Both fields are attached **only to packages the graph actually places**, and are absent otherwise. This matters because generators differ enormously: a Trivy filesystem scan placed all 518 packages of this repo, while a Syft directory scan of the same repo placed 1 of 527 (Syft does emit relationships for npm, where it placed 68 of 69). Stamping `direct: false` on everything a generator failed to mention would be the positive claim "none of these are yours" about a document that never said. Neither generator's shape is assumed: Trivy roots the graph at `metadata.component` and hangs one application node per manifest above the libraries, while Syft's `metadata.component` is a `file` that is not a graph node at all and the scanned project appears as an ordinary library with no incoming edge, so direct-ness is derived from the graph's entry points rather than from either convention.
  One honest difference from the native path remains, and only for a library maintainer scanning their own repository: Bundler's `DEPENDENCIES` omits a gemspec project's own runtime dependencies, so the native audit deliberately promotes them to direct, whereas an SBOM shows them hanging off the project's own package node and they read as transitive with that node at the head of the path. There is no reliable cross-ecosystem way to recognise "this component is the project itself", so the SBOM path reports what the graph says instead of guessing.
- **Licences on the `--sbom` path.** A cross-ecosystem audit reported an empty licence column while the native Ruby audit filled it in. deps.dev serves the pinned version's SPDX licences on the version endpoint still_active already calls for advisories and the release date, so this closes the gap with no extra request, no new host, and no new dependency; it was simply a field being fetched and discarded. Both paths now render through one helper, so a licence reads identically whether it came from RubyGems or deps.dev, including a single-element SPDX expression like cargo's `Apache-2.0 OR MIT`, which passes through untouched rather than being split. A package that declares no licence stays `nil` rather than becoming a blank string, so "none declared" cannot be mistaken for a present-but-empty value.
- **The `--sbom` path now carries the same version signals as the native audit**: `libyear` drift, a prerelease/ahead-aware `up_to_date`, the `latest_version` string, and (when the SBOM marks CycloneDX dev-vs-prod scope) a `production` boolean so a consumer can separate prod risk from test debt. A private/alternative registry named in a PURL's `repository_url` is refused a public-by-name lookup (the cross-ecosystem dependency-confusion guard), and a pinned version deps.dev can't resolve reads `unknown` rather than riding the fresh package date to a false `ok`.
- **`--sbom=PATH` audits a CycloneDX SBOM cross-ecosystem**, so the maintenance lens travels beyond Ruby: point it at a Syft/Trivy-produced SBOM and still_active assesses every `npm`, `pypi`, `cargo`, `go`, `maven`, and `nuget` package the same way it does gems (latest release date, archived repo, advisories, OpenSSF Scorecard, lifecycle `status`), sourcing signals from deps.dev and ecosyste.ms instead of Bundler. Mutually exclusive with `--gemfile`/`--gems`, and honours the same output-format flags as the Gemfile path (`--sarif` for GitHub Code Scanning, `--markdown` for CI step summaries, `--terminal`, `--json`), so formatting is independent of whether the input was a Gemfile or an SBOM; findings are named `ecosystem/name`, and SARIF anchors them to the SBOM file since there is no lockfile to annotate. The JSON shape differs from the Ruby audit, so it deliberately omits the `$schema` contract. `--baseline` needs the native audit's gems/ruby snapshot, which a cross-ecosystem SBOM can't honestly supply, so it errors loudly rather than silently falling back to JSON (`--cyclonedx` is supported and emits an enriched SBOM; see its own entry above). A cross-ecosystem finding's suppression identity (for `--ignore` and `.still_active.yml`) is `ecosystem/name` (e.g. `npm/left-pad`), version-independent and matching what the SARIF `suppressions[]` and the fail-if gates key on, not the composite `ecosystem/name@version` result key. Results are keyed `ecosystem/name@version` so nothing collides and overwrites, not a same-named package across two ecosystems nor two versions of one package pinned by different subprojects of a monorepo (a lockfile resolves one version per name, a merged SBOM doesn't), and each dependency carries its `activity_level` and `status`. The SBOM is treated as **untrusted input**: the only things read from it are ecosystem/name/version, the repository is discovered from deps.dev (never a lockfile-supplied URL, so a hostile SBOM can't redirect a lookup), and anything deps.dev doesn't index degrades to `unknown` rather than a fabricated `ok`. Packages it can't assess (unsupported ecosystems, a component with no version or PURL, **and** a dependency whose lookup raised, e.g. a rate-limited or flaky deps.dev) are surfaced in an `unassessable` list and a stderr count, never silently dropped, so a transient upstream hiccup can't shrink the audit scope invisibly and let it read "all clear" while ignoring the deps it skipped. A present-but-unreadable SBOM (truncated, or not CycloneDX) errors rather than degrading to an empty clean report. OS packages land in `unassessable` too; the differentiated play is maintenance, not vuln scanning, so compose Trivy/Grype for CVEs.
- **Tokenless GitHub repo signals via [ecosyste.ms](https://ecosyste.ms).** Without a GitHub token the live API caps at 60 requests/hour, unusable past a handful of gems; still_active now falls back to ecosyste.ms (5000 anonymous requests/hour) for GitHub repos' archived + last-commit signals, so a large Gemfile audits cleanly with no token. GitHub-only by design (ecosyste.ms doesn't track commit recency for GitLab/Codeberg, so those keep their own clients); a configured token still takes precedence (freshest data, and it carries `--unreleased-commits`). Requests identify still_active in the User-Agent, and an optional `--ecosystems-email` / `STILL_ACTIVE_ECOSYSTEMS_EMAIL` joins ecosyste.ms's "polite pool" (higher rate limit) as a courtesy to the free service. ecosyste.ms data is CC-BY-SA 4.0 and attributed in the README.

- Each gem now carries the OpenSSF Scorecard **`Maintained` sub-check** (`scorecard_maintained`, 0.0-10.0) alongside the aggregate `scorecard_score`. The sub-check scores recent commit and issue activity directly, the question still_active exists to answer, and it was already present in the deps.dev response still_active fetches (previously discarded). `nil` when a project has no scorecard, deliberately distinct from `0.0` ("measured: unmaintained") so absent data never reads as healthy.
- A single categorical **lifecycle `status`** per gem and a project-level `summary.status`, so a machine/LLM consumer or another tool reads one verdict instead of re-deriving it from `activity_level` + `archived` + `vulnerability_count`. Worst-first: `dead` (dormant/archived **and** carrying an unpatched advisory; no one is fixing it, migrate) > `vulnerable` (a fixable advisory on an actively-released gem) > `archived` > `stale` > `legacy` (long-dormant but **clean**: feature-complete, low risk, the "done gem" that recency alone wrongly flags) > `ok` > `unknown` (never silently `ok`). An EOL Ruby floors the project at `vulnerable`. **archived is not dead:** a repo archived while the gem still publishes recent releases (development moved to a monorepo) reads as `stale`, not dead; only a genuinely dormant archived repo is `archived`. This is a display/threshold convenience over the raw fields, not the numeric 0-100 composite removed earlier (which let missing data read as perfect health). Documented in `docs/schema.md`. Additive, so `schema_version` stays `1`.

### Fixed

- **The `--sbom` JSON output is documented.** It is a 3.0 headline feature that emits `schema_version: 1` while `docs/schema.md` described only the Gemfile audit's shape, so two structurally different documents both claimed version 1 and one of them had no written contract at all. The cross-ecosystem envelope, its `unassessable` entries, and the fields specific to that path (`ecosystem`, `name`, `purl`, `production`, `direct`, `dependency_path`, `version_unresolved`) are now documented, along with the rule for telling the two apart: check for `gems` versus `dependencies`, not `schema_version`. A doc-consistency spec now fails if the `--sbom` path emits a field that document never mentions, since unlike the native output there is no JSON Schema to catch it.

- **Verified against five real SBOM generators, not one.** The `--sbom` path is now exercised in the test suite against verbatim output from Syft, Trivy, `npm sbom`, `cyclonedx-npm` and `cyclonedx-py`, committed as fixtures rather than hand-written. They disagree about nearly everything a reader could naively depend on: three CycloneDX spec versions (1.5, 1.6, 1.7), four `metadata.component` types including absent entirely, and five mutually incompatible bom-ref conventions (a PURL with a `package-id` qualifier, a bare UUID, `name@version`, a pipe-delimited parent/child path, and a requirements-file line number). Given the same project all five now produce the same verdict, and the suite fails if a future change makes one of them disagree. This closes the gap behind both SBOM bugs found before it: a synthetic fixture only ever encodes the shape whoever wrote it already had in mind.


- **An impossible `--sbom` output mode is rejected before the audit runs, not after.** `--sbom --baseline` read the SBOM, canaried deps.dev, and ran the entire cross-ecosystem assessment (a request per package to deps.dev, ecosyste.ms and the forges) before rejecting the combination with exit 2. The incompatibility is knowable from the flags alone, so all of that work was bought and thrown away: measured at 3 seconds for a three-package SBOM, which on a real one is minutes of wall time and hundreds of calls against free services. It now errors immediately, before the SBOM is read.

- **A `--sbom` audit no longer reports the scanned project as one of its own dependencies.** Syft lists the project it scanned as an ordinary `library` component with a purl, indistinguishable by shape from a real dependency, so still_active assessed it: no registry entry means no releases, which reads as critically stale. A user pointing Syft at their own repository, the workflow the README recommends, got a confident red verdict about their own code, and `--fail-if-critical` fired on it. Observed on a real Syft scan of an npm project, which reported the project itself as `status: legacy`, `activity_level: critical`. There is also a latent version of this that was not observed but is worth naming: the project is looked up by its own name, so a public package sharing that name and version would supply the data reported for your local project (in both cases seen here the version did not resolve, so the result was a false stale verdict rather than borrowed data). The dependency graph tells them apart, since the project is the thing nothing depends on; it is now dropped rather than surfaced as unassessable, the same treatment CI actions and opaque binaries already get, because it is not a dependency we failed to assess, it is not a dependency. The rule is conservative on both halves: it only considers library components, so Trivy's application-typed root and per-manifest nodes are unaffected, and it requires the component to actually pull something in, so a dependency whose parent edge a generator failed to record is never dropped for looking parentless. An SBOM with no dependency graph is unchanged. Verified against real output: a Syft npm scan drops only the project (69 packages to 68), a Trivy scan of this repo is untouched at 518, and a Syft directory scan drops only a local fixture project.

- **SARIF EOL dates are no longer a day early east of UTC.** endoflife.date publishes a bare calendar date (Ruby 3.2's `eol` is the string `2026-03-31`), which `Time.parse` reads as local midnight; the SARIF renderer then converted it to UTC before formatting, rewinding it one day for every user in a positive-offset zone (CEST midnight is 22:00 UTC the previous day). An EOL Ruby or a runtime-ceiling receipt (SA006, SA009) therefore reported a date the runtime was in fact still supported on, and disagreed with the markdown and terminal output, which never applied the shift. The date is now rendered as parsed. Release timestamps, which are real instants carrying their own zone, are unaffected.
- **A patched version is no longer reported vulnerable while an advisory's backport fixes are still propagating.** deps.dev's per-version `advisoryKeys`, the discovery source for every cross-ecosystem advisory (and the second source on the native Ruby path), mirrors OSV/GHSA data with an ingestion lag. Advisories are routinely *amended* after publication: a CVE lands with a fix on the current release line, maintainers backport to the older supported lines, and the advisory is then amended to carry those branch ranges. Until deps.dev re-ingests, it keeps serving the pre-amendment record, whose broader range still covers versions the amendment has since marked patched. Live receipt: `GHSA-mh99-v99m-4gvg` was published 2026-07-24 as a single `introduced 0 / fixed 5.0.8` range and amended 2026-07-31 to carry the 1.1.17, 2.1.3 and 3.0.3 branches; hours after the amendment deps.dev still answered from the old record, so `--sbom` reported the fully patched `brace-expansion` 1.1.18 and 2.1.4 as `status: "vulnerable"` where `npm audit` correctly reported none. still_active now confirms each deps.dev-discovered advisory against OSV's own `/v1/query`, deps.dev's upstream, which applies the declared ranges per ecosystem and reflects an amendment immediately, and drops the ones OSV says do not apply to the audited version. The window reopens with every backported fix, so this is a standing correction rather than a workaround for one stale record. A dropped advisory is named on stderr, so the one path that can turn a red run green always leaves a trace. (It is lag, not a parsing defect on deps.dev's part: 341 multi-branch advisories across npm/rubygems/pypi/cargo were compared against OSV over 589 version checks, and every one agreed.) Dropping a finding is the one direction this tool must never get wrong, so it needs positive contradiction on every count: the advisory came from deps.dev alone (a ruby-advisory-db verdict is never overruled, it matches versions itself and is the Ruby authority), OSV served a record for it that names the package under that exact ecosystem and spelling, and the query for that exact version succeeded without listing it. A failed query, an unmapped ecosystem, a name OSV spells differently, a record holding no version data for the package, or an answer that isn't readable end to end all keep the advisory. That last one matters more than it sounds: OSV's genuine all-clear is a bare `{}` with no positive marker of its own, and OSV paginates once a query exceeds 20 seconds (a latency trigger, so it can land on any package under load), so a truncated page is treated as "we don't know", never as "clean". Costs one request per advisory-bearing package.
- **A private-source gem is no longer linked to the public rubygems.org page.** `ruby_gems_url` was set to `rubygems.org/gems/<name>` for any gem with versions, including one resolving from a private source, where that URL is a public name collision (for `sidekiq-pro`, the `0.0.3` squat-warning decoy) rather than the gem the user installs. It is now set only for a gem that actually lives on public rubygems.org, the same #43 guard the repository-URL substitution already applies.
- **An Artifactory-sourced gem is no longer reported `(YANKED)` when its real host is a legacy private registry.** Artifactory's `/api/v1/versions/<gem>.json` merges metadata from a virtual repo's member remotes; when a member (a legacy host like Contribsys) can't answer it, the merge returns only whatever rubygems.org holds for the name, which for `sidekiq-pro` is a `0.0.3` squat-warning placeholder. still_active read that endpoint first, so the installed version was absent from the list and looked yanked. It now reads the RubyGems compact index (`/info/<gem>`, what Bundler resolves through) instead, listing exactly the versions the repo can resolve, with the versions API demoted to dating those versions and AQL kept only as a last resort for hosts serving no compact index (and no longer presenting its cache timestamp as a release date). A side benefit: the compact index's per-version Ruby requirement and dependency constraints let the runtime-ceiling and poison-pill checks work on Artifactory sources for the first time.
- **SARIF `tool.driver` version fields are populated and spec-correct.** `version` was null, so a consumer reading `tool.driver.version` (rather than `semanticVersion`) saw nothing, and `semanticVersion` carried the RubyGems version verbatim (`3.0.0.rc4`), which is not valid SemVer 2.0.0 for a prerelease. Now `version` carries the free-form gem version and `semanticVersion` the SemVer form (`3.0.0-rc4`); final releases like `3.0.0` were already valid.
- **Cross-ecosystem SARIF no longer reads as a Ruby audit.** The `--sbom` path emitted the native Gemfile audit's Ruby-worded SARIF rule catalog, so a Go/npm/pypi repo's GitHub Code Scanning alerts were titled "Gem source repository is archived", advised `bundle update <gem>`, and referenced `Gemfile.lock`/RubyGems in the rule detail. The catalog now has an ecosystem-neutral flavour for SBOM runs (titles and guidance say "package"/"dependency"), and the native-only SA006 (Ruby runtime EOL), which the cross-ecosystem path can never emit, is dropped from the SBOM catalog rather than advertised in a non-Ruby repo. Per-result finding messages were already neutral; this fixes the rule metadata GitHub renders as the alert title and detail. The native Gemfile SARIF is unchanged (still `gem`-worded, SA006 present).
- **A stale pre-release no longer corrupts the up-to-date signal.** A pre-release older than the latest stable (an `8.1.0.rc1` still listed after `8.1.2` shipped, or a decade-old `rc` on a gem long past it) was treated as a live upgrade target: `up_to_date` compares the version in hand against it, so any current version read as up to date and a gem that was actually behind got the "futurist" marker, while the pre-release column filled with superseded rcs. The latest pre-release is now kept only when strictly newer than the latest stable (or when there is no stable release at all, where it is the only signal), so the column, the `up_to_date` field, and the emoji agree. Genuine upcoming pre-releases still surface. On a real bundle this was mislabelling roughly twenty gems.
- **`--baseline` now honours a committed `.still_active.yml`.** The PR-diff gate was the only gate that ignored the suppression list: a maintenance regression the audit and SARIF gates already accept still tripped `--baseline` the moment the dependency was added, with no way to accept it short of merging it to the baseline first. An accepted regression is now moved out of the CI-failable set and shown under an "Accepted (suppressed via `.still_active.yml`)" section with its reason, so the acceptance stays visible rather than silently vanishing. Only maintenance kinds a bare gem+signal entry can cover are accepted (archived/staleness map to `activity`/`libyear`); a newly introduced vulnerability still fails, since suppressing one needs an explicit advisory id the diff regression doesn't carry.
- **The fail-open on the vulnerability gate is closed on both paths.** `--fail-if-vulnerable=<severity>` no longer passes a confirmed advisory that carries no CVSS score (an unscored advisory read as "below threshold" and cleared the gate, worst for a freshly disclosed CVE); it now fails closed with a per-gem stderr note (see Upgrading). And the native path no longer drops a confirmed advisory when its deps.dev detail fetch fails (429/timeout/5xx); it previously `filter_map`'d the failure away and zeroed `vulnerability_count`, it now keeps a minimal advisory so the finding survives and the fail-closed logic applies.
- **deps.dev CVE aliases are surfaced correctly.** The v3alpha API returns aliases as bare id strings, not objects; the parser read `a["id"]` on a string and dropped every alias, so cross-referenced CVE/GHSA ids vanished. It now tolerates both shapes (and coerces a drifted non-string alias to a string, warning once, so it can't crash the advisory merge and read a vulnerable gem as clean).
- **A multi-range advisory no longer hides a stuck cap or names a downgrade as the fix.** OSV lists a fixed version per affected range; the below-the-fix check used the global-minimum fix, so a downgrade to an older line could read as "patchable in place" (a false negative) or be named as the fix. It now considers only fixes above the version in hand.
- **A pinned version the registry can't resolve reads `unknown`, not `ok`.** A nonexistent or yanked pinned version on the `--sbom` path rode the fresh package date to a false `ok`; it now reports `unknown`, with a single retry distinguishing a real 404 from a transient miss.
- **Graceful degradation on real SBOM/CLI input.** A git-scheme or scp `SOURCE_REPO` URL from deps.dev now parses correctly (recovering repo signals and silencing a warning flood); a malformed PURL (`pkg:npm/@1.0.0`, bad `%`-encoding) degrades to `unassessable` instead of backtracing and dropping every other dependency's verdict; and bad CLI input exits 2 with a friendly error instead of a stack trace (see Upgrading).
- **The published JSON Schema matches real output.** It had rejected any report containing a vulnerability, because OSV enrichment adds fields (`osv_severity`, `fixed_versions`, and more) the strict `additionalProperties: false` schema didn't list. The schema now covers them (and the poison/below-the-fix keys), and the contract test validates enriched output so it can't drift silently again.
- **A current Go dependency no longer reads as "behind".** Go module versions carry a `v` prefix (`v2.0.1`) that `Gem::Version` can't parse, so the up-to-date comparison silently failed and the `--sbom` terminal/markdown table painted a `v2.0.1 -> v2.0.1` upgrade arrow on a package already on its latest release. The prefix is now stripped before comparison (a no-op for digit-first rubygems/npm/pypi/cargo versions).
- **A cross-ecosystem package with a "wrong" default version no longer reads as abandoned.** deps.dev's `isDefault` flag is not reliably the latest release: for `cargo/wasi` it points at `0.7.0` (2019) while `0.14.7` (2025) ships, and for `pypi/httpx` it points at a `1.0.0.dev3` prerelease over the `0.28.1` stable. The `--sbom` path trusted it, so an actively-maintained package rendered as years-stale (a false SA002 "no release in N years", which can fail `--fail-if-critical` and pollute Code Scanning) and a downgrade was shown as an upgrade. still_active now ranks a package's versions and takes the newest *stable* release, falling back to `isDefault`/newest-by-date only when no stable version parses.
- **SemVer build metadata no longer breaks the up-to-date comparison.** A cargo version like `1.0.4+wasi-0.2.12` couldn't be parsed by `Gem::Version` (the `+build` suffix), so `--sbom` painted a "behind" arrow on an already-current crate. Build metadata (which SemVer 2.0.0 says MUST be ignored for precedence) is now stripped before comparison, and the terminal version column distinguishes "behind" from "couldn't compare" (showing the version plainly rather than a false upgrade arrow, matching the markdown "unsure" state).
- **The terminal summary says "dependencies", not "gems", for a cross-ecosystem `--sbom` audit** (calling npm/cargo/go packages "gems" is a Ruby-ism); the native Ruby audit still says "gems".
- **A GitHub funding link is no longer mistaken for a repository.** deps.dev sometimes returns a `SOURCE_REPO` of `https://github.com/sponsors/<user>` (a funding page); parsed as `owner/repo` it 404'd and left a blank "last commit" cell. Reserved GitHub top-level paths (`sponsors`, `orgs`, `apps`, ...) are now treated as "no repo", and the markdown "last commit" column shows the unsure marker instead of an empty link when a date is missing.

## [2.0.0] - 2026-06-14

### Upgrading to 2.0

2.0 is a major bump because two changes can alter `--fail-if-*` outcomes on upgrade (the CLI flags and JSON `schema_version` are otherwise backward-compatible):

- **Transitive by default.** Maintenance signals now cover the full resolved lockfile, so a CI gate can newly fail on a transitive critical/vulnerable/outdated gem. Add `--direct-only` to restore the pre-2.0 declared-deps scope.
- **Activity recalibration.** The "ok" ceiling moved 12 → 18 months and the level is release-driven, so some gems are reclassified. Tune with `--safe-range-end` / `--warning-range-end`.
- **Baselines:** re-capture your `--baseline` JSON after upgrading. The transitive expansion shows the new gems as additions (and any unhealthy transitive deps as regressions) on the first run.

### Added

- The `--json` output is now a **versioned, contract-tested machine schema** ([`docs/still_active.schema.json`](docs/still_active.schema.json), JSON Schema 2020-12), carried as a `$schema` URL so the output is self-describing, and it gains a `summary{}` digest, the audit's headline posture (total / direct / transitive, the activity-level breakdown, archived / up-to-date / outdated counts, and vulnerability totals) in one object so a machine or LLM consumer reads it without iterating every gem. The terminal summary line now derives from the same digest, so the human and machine summaries can't drift. Unlike SARIF (findings-only) and CycloneDX (SBOM-only), this is the complete correlation-layer view. (#33)
- Maintenance signals (stale releases, archived repos, last-commit age, advisories, libyear) now cover the **full transitive lockfile graph** by default, not just declared dependencies, matching libyear-bundler and the CVE scanners still_active composes with. Each gem carries `direct: true|false`, and a flagged transitive gem carries a `dependency_path` back to the direct dependency that pulls it in (e.g. `["rails", "actionpack", "rack"]`), turning an un-actionable transitive finding into an actionable "replace your direct gem" in terminal, markdown, JSON, and SARIF output. `--alternatives` stays **direct-only** by design (you can't swap a gem you didn't choose). `--direct-only` opts back to the previous declared-deps-only scope. Because this multiplies the number of repo/version lookups, prefer running on a schedule rather than per-commit (see the README). (#60)
- A committed `.still_active.yml` config file, with granular finding-level suppression replacing the all-or-nothing `--ignore`. `--ignore=GEM` drops a gem from every gate at once, so accepting one unfixable advisory also hid that gem going archived or getting a *new* CVE. The file's `ignore:` block keys suppressions by advisory id and/or signal (`activity` / `vulnerability` / `libyear`), each with an optional `reason` and `expires` date. A vulnerability suppression must name an explicit advisory id, so a newly disclosed CVE on the same gem still fails; a lapsed `expires:` makes the finding re-surface as a normal failure (Trivy-style) rather than rotting silently, and a suppression that names a gem not in your dependency graph (a typo, or a gem you've since removed) is reported as a warning, so dead entries surface instead of lingering. The file also mirrors the policy flags (gates, thresholds, `output`, `alternatives`, `unreleased_commits`, `direct_only`) with precedence CLI flag > env var > config file > default, and an `import: [.bundler-audit.yml]` opt-in folds bundler-audit's accepted-advisory list in so teams keep one ignore list. Secrets (tokens) and invocation-specific paths are deliberately not read from the file, so a committed config never carries a credential. Suppressed findings still appear in JSON/terminal/markdown output and are marked in SARIF as native `suppressions[]` entries (with the reason as justification), so GitHub Code Scanning renders them dismissed rather than open. (#46)
- `--unreleased-commits` adds an `unreleased_commits` count per gem: commits on the default branch since the latest release's tag, the "unreleased work" signal no Ruby tool surfaces today (only GitHub's UI shows it). It distinguishes a gem that looks stale but is genuinely done (no unreleased work) from one with a recent release but a pile of merged-but-unreleased fixes. Opt-in and GitHub-only: it adds one API call per GitHub-hosted gem (the tag is resolved from the RubyGems version, trying `v1.2.3` then `1.2.3`), non-GitHub sources report `null` (the signal is duck-typed via `respond_to?`, no base-class interface), and it is purely informational, never gating a run. Inflated for monorepos and release-branch projects, so it is documented as a lead, not a verdict. (#32)
- Forgejo/Codeberg repos are now a recognised source for the archived and last-commit signals, alongside GitHub and GitLab. A gem whose canonical `source_code_uri` points at `codeberg.org` previously fell through to no repo signals at all; it now resolves through a new `ForgejoClient` (the Gitea `/api/v1` surface every Forgejo/Gitea instance shares), so the host is a parameter for later self-hosted support. Reads are anonymous by default; `STILL_ACTIVE_FORGEJO_TOKEN`/`CODEBERG_TOKEN` only raise the rate limit or reach private repos. Codeberg-hosted repos are correctly left out of deps.dev OpenSSF Scorecard lookups (deps.dev indexes only github.com/gitlab.com) rather than minting a bogus `github.com/owner/name` project id. (#31)
- JSON output now includes a derived `activity_level` per gem (`"ok"`, `"stale"`, `"critical"`, `"archived"`, or `"unknown"`), so a machine or LLM consumer reads still_active's maintenance verdict directly instead of re-deriving it from the raw dates. Documented in `docs/schema.md`. (#33)
- JFrog Artifactory gem registry support: fetches versions from `.jfrog.io` RubyGems-compatible registries via the versions API with an AQL search fallback. Auth reuses Bundler's per-source credentials when present, otherwise a global token via `--artifactory-token` or `STILL_ACTIVE_ARTIFACTORY_TOKEN` (requires a matching `--artifactory-host` / `STILL_ACTIVE_ARTIFACTORY_HOST`).

### Changed

- Per-gem date fields in `--json` (`last_commit_date` and the `*_release_date` fields) are now ISO8601 UTC (e.g. `2026-01-02T01:04:05Z`), matching `generated_at`, and the published schema marks them `date-time`. They were previously serialized in Ruby's default `Time` format in the machine's local timezone (`2026-01-02 03:04:05 +0200`), so a consumer parsing them got an inconsistent, machine-dependent value. Consumers that parsed those fields should re-check their date handling.
- A gem's `archived` flag and last-activity date now come from a **single repository call per gem instead of two**, halving the repo-signal API requests (and easing the rate limit on the full-transitive audits of #60). The repo object already carries both the archived flag and a last-activity timestamp (GitHub `pushed_at`, GitLab `last_activity_at`, Forgejo `updated_at`), so the separate "latest commit" call was redundant: across 11 GitHub repos plus GitLab and Forgejo checks, that timestamp matched the default-branch commit date **to the day**. `last_commit_date` is now that repo last-activity timestamp; it tracks the last commit in practice and, since the activity verdict is release-driven (#32), this doesn't change classifications. (#35)
- A GitHub rate-limit response is now waited out and retried once when its reset is near (at most 60 seconds away), instead of silently dropping that gem's repo signals. GitHub's concurrent fan-out can trip the secondary/burst limit even with a token, especially now that the full transitive graph is audited (#60); honouring the `Retry-After` / `x-ratelimit-reset` header lets the run self-heal rather than return blanks. Under the async reactor the wait yields to other fibers rather than blocking. A far-away reset (hourly-limit exhaustion) is not auto-waited; it still warns and moves on (set a token, or run less often). (#35)
- A gem's activity level is now driven by release recency rather than the most recent of release-or-commit. A single trivial commit (a rubocop autofix, a README tweak) on a gem whose last real release was years ago previously masked the release drought and read as healthy; the commit date is now context only, and stands in for the level solely when a gem has no releases at all (e.g. a git-sourced gem). The "ok" ceiling also moves from 12 to 18 months, calibrated against real RubyGems release cadence rather than the npm-derived annual convention, since healthy mature gems (mime-types, bcrypt, mail) routinely go a year or more between releases. (#32)

### Fixed

- `--baseline` no longer crashes when pointed at a JSON file that isn't a still_active snapshot (a top-level array, a non-object `gems` section, or a gem/`ruby`/field of the wrong type); it exits 2 with a message naming the problem, honouring the exit-code contract documented since 1.4.0.
- SARIF `SA002` (AbandonedGem) now uses the same release-driven activity level as the rest of the tool, instead of its own separate commit-date threshold. A gem with recent commits but a years-old release was silently missed by the SARIF/code-scanning output (the inverse of the terminal fix), and the message reported commit age ("no commits in 2.0 years") rather than the release gap that actually triggered the finding ("no release in 4.4 years"). SA002 now fires on the `:critical` tier (no release in over 3 years; the last commit date is used only for gems with no releases, e.g. git-sourced), and the message names the real signal. (#32)
- CycloneDX SBOM: every versioned component now carries a purl. git/path gems were previously emitted as versioned `type:library` components with no purl, which made Datadog SCA and strict CycloneDX consumers reject the document. The Ruby runtime component also gains a `pkg:generic/ruby` purl and a `ruby-lang:ruby` CPE so interpreter CVEs can match. (#45)
- deps.dev OpenSSF Scorecard lookups now keep the full GitLab subgroup path. `extract_project_id` truncated `gitlab.com/group/subgroup/project` to `gitlab.com/group/subgroup`, so the score was fetched for the wrong project on any nested GitLab namespace. (#44)
- GitHub Packages version lookups now URL-escape the (lockfile-derived) gem name, matching the Artifactory path. A name with URL-unsafe characters previously raised `URI::InvalidComponentError`, which was swallowed and silently dropped that gem from the audit. Defensive hardening for the untrusted-lockfile stance; the GitHub token is never sent off the fixed `rubygems.pkg.github.com` host. (#50)
- `--gemfile` is now honoured under `bundle exec`. Dependency loading and the Ruby-version lookup derived their target from a memoized `Bundler.definition` / the ambient `BUNDLE_GEMFILE`, so an explicit `--gemfile` was ignored; both now read the given path directly. (#42)
- `HttpHelper` no longer crashes on a 3xx response with a missing or malformed `Location` header. `uri + nil` raised `ArgumentError` and a malformed value raised `URI::InvalidURIError`, neither rescued, so the gem was silently dropped; both now return nil with a warning. (#39)
- Gems from an unqueryable private source (Gemfury, Gemstash, geminabox, a private mirror) are no longer silently looked up on public rubygems.org. A private name with no public match reported blank data, and one that collided with a public gem reported the *public* gem's versions/dates/libyear/repository as if they were the private gem's. still_active now detects a non-rubygems.org rubygems source, warns, and skips both the public version lookup and the public repository-metadata fallback rather than substituting public data. (#43)
- A gemspec project's (or local Rails engine's) runtime dependencies are now audited. The `gemspec` / `gem path:` directive surfaces the local gem's *development* deps in the lockfile's DEPENDENCIES, but its *runtime* deps appear only as that gem's nested lockfile deps, so a maintainer auditing their own repo never saw the deps they ship. still_active now expands local path-sourced gems' runtime deps (transitively through nested engines) into the audited set, still parsing the lockfile only and never the gemspec. (#41)

### Security

- Credentials are no longer retained on a redirect that changes the port or downgrades the scheme. The redirect follower previously dropped auth headers only when the host changed, so a same-host redirect to a different port (a different service) kept the token; it now requires a full-origin match (scheme, host, and port) and refuses a non-https redirect.
- still_active no longer evaluates the audited project's Gemfile. `gemfile_dependencies` loaded it via `Bundler.definition`, executing arbitrary Ruby straight from the Gemfile, an unauthenticated RCE when run on an untrusted repository (e.g. CI on a pull request). It now parses `Gemfile.lock` directly with a side-effect-free parser, which also neutralizes `Bundler::LockfileParser`'s own `PLUGIN SOURCE` registry resolution. (#37)
- `HttpHelper` now caps a response body at 16 MiB, streaming the read rather than buffering the whole body. A source URL is lockfile-derived and a `*.jfrog.io` host is attacker-registerable, so an unbounded body was an unauthenticated OOM triggerable by lockfile content alone. (#40)
- Markdown output now escapes untrusted metadata. Gem names, licences, versions, repository URLs, and advisory ids drawn from registry/repo metadata, the Gemfile/lockfile, `--baseline`, or `--gems` could otherwise forge table columns or links, break a code span, or inject a list item/heading into a PR comment. GFM escaping is centralised in `StillActive::MarkdownEscape` and applied to both the audit table and the PR diff. (#38)
- The Ruby Toolbox catalog (used by `--alternatives`) is now fetched via `URI.parse(url).open` instead of `URI.open`, resolving a CodeQL `rb/non-constant-kernel-open` finding. The URL is a constant repo-archive link with no injection path, so this is hardening rather than a fix for a reachable issue.

## [1.6.0] - 2026-06-08

### Added

- `--alternatives` surfaces up to three maintained alternative gems for any dependency still_active flags as archived or critically abandoned, drawn from the [rubytoolbox/catalog](https://github.com/rubytoolbox/catalog) category data and ranked by total RubyGems downloads. Presented as **leads to verify, not vetted recommendations** — same Ruby Toolbox category does not guarantee a drop-in replacement — reflecting that Ruby has no authoritative successor metadata the way npm (`deprecate`), Go (`// Deprecated:`), or NuGet (alternate-package) do. Opt-in and best-effort: the catalog is fetched once and cached under `XDG_CACHE_HOME` with a 7-day TTL, any fetch/parse failure degrades to silence, and nothing here can block a run or affect `--fail-if-*` exit codes. Leads render in terminal (a dimmed sub-line), markdown (an Alternatives section), JSON (an additive `alternatives` array), and SARIF (appended to the SA001/SA002 result messages); CycloneDX is unchanged. With the flag off, terminal output shows a one-line discoverability hint on flagged gems. Silent when the catalog has no entry for the gem (the common case for niche/long-tail gems). Closes #28.

### Changed

- The `async` runtime dependency now requires `>= 2.2` (previously unconstrained). 2.2.0 is the verified real minimum — earlier 2.x releases hit a fiber-scheduler `io_read` bug under still_active's concurrent fan-out. A new CI job installs every runtime dependency at its declared gemspec floor and runs the suite on the minimum supported Ruby, so an under-set floor now fails loudly instead of silently.

## [1.5.0] - 2026-05-23

### Added

- `--cyclonedx[=PATH]` emits a CycloneDX SBOM (stdout by default, or to a file) so the dependency graph plus still_active's signals flow into Trivy / Dependency-Track / Snyk. Emits **1.6 by default** — the version mainstream consumers ingest today (`cyclonedx-core-java` / Dependency-Track and `cyclonedx-go` / Trivy both cap at 1.6 as of 2026) — with `--cyclonedx-version=1.7` to opt into the latest. Gem name/version/purl/licenses map to native fields; maintenance signals (archived, OpenSSF score, libyear, last commit, yanked) ride in `still_active:`-namespaced `properties`; vulnerabilities map to the top-level `vulnerabilities[]`. The `serialNumber` is content-derived (two SBOMs of the same lockfile are byte-identical apart from the generation timestamp), so SBOMs diff cleanly.
- Dependabot/Renovate awareness: when a run is detected as bot-authored (primarily via the PR author in the GitHub event payload — `pull_request.user.login`, the same authoritative signal `dependabot/fetch-metadata` uses, which unlike `GITHUB_ACTOR` survives a human re-running the workflow — falling back to `GITHUB_ACTOR`, a `dependabot/`/`renovate/` branch, or the commit subject including Dependabot's default unprefixed `Bump X from Y to Z`), output leads with a narrative header (markdown/terminal/baseline-diff: "Dependabot bump: rack 2.0.0 → 2.0.6") and JSON gains a top-level additive `pr_context` (`{ bot, bumps: [{ gem, from, to }] }`). Bump extraction tolerates any configured `commit-message.prefix`/scope (`chore(deps):`, `deps:`, …) once the bot is confirmed, while detection stays conservative to avoid false positives on human commits. Best-effort: false negatives lose only the narrative, never a finding; SARIF is unaffected. See `docs/schema.md`.
- A warning is emitted when mutually-exclusive output flags are combined (`--baseline`/`--sarif`/`--cyclonedx`), naming which one wins, and when `--cyclonedx-version` is set without `--cyclonedx`.
- Dual-source vulnerability data: when `bundler-audit` is installed (with a current `bundle audit update` checkout), still_active reads the `rubysec/ruby-advisory-db` advisories through bundler-audit's own loader and merges them with deps.dev results, deduplicating on shared identifiers. Each advisory carries a `source` field (`deps.dev`, `ruby-advisory-db`, or `merged`); deps.dev is preferred for CVSS/title/vector and ruby-advisory-db fills gaps. Opt-in by composition — no second source unless `bundler-audit` is present; falls back silently to deps.dev only otherwise (with a one-line hint to run `bundle audit update`). Closes the "why do bundler-audit and still_active disagree?" gap. See `docs/schema.md` and `docs/rules.md` (SA003).
- Gem license surfaced from the RubyGems versions payload we already fetch (no extra request). Shows as a `License` column in terminal and markdown output and as an additive `license` field (SPDX identifier, comma-joined when a gem declares more than one) on the JSON per-gem record. `nil`/`-` for git/path sources where no RubyGems metadata exists. See `docs/schema.md`. Read-only metadata only — license *policy* (allow/deny gating) stays the domain of `license_finder`.

## [1.4.2] - 2026-05-22

### Fixed

- Replaced an opaque `NoMethodError` on `nil.specs` with `StillActive::MissingLockfileError` and a clear "run `bundle lock` first" message when a Gemfile exists but no `Gemfile.lock` is reachable. Caught during the still_active-action self-test wiring.

## [1.4.1] - 2026-05-22

### Fixed

- `still_active --gems=X` (or any invocation that doesn't need a Gemfile) crashed with `Bundler::GemfileNotFound` when run from a directory without a Gemfile in the tree. `Config#initialize` eagerly called `Bundler.default_gemfile`. Now `gemfile_path` resolves lazily on first read and falls back to `./Gemfile` when none is reachable.

## [1.4.0] - 2026-05-22

### Added

- `--sarif[=PATH]` emits SARIF 2.1.0 for GitHub Code Scanning. Findings appear in the Security tab and as inline annotations on `Gemfile.lock` in pull requests. Default path: `still_active.sarif.json` (pair with `github/codeql-action/upload-sarif@v3`). `--sarif=-` writes to stdout. Rule reference (SA001–SA007) in `docs/rules.md`. Stable `partialFingerprints` (rule + gem + advisory) keep alert IDs constant across `bundle update`s.
- `--baseline=FILE` compares the current run against a baseline still_active JSON snapshot and emits a markdown delta report. Designed for PR review: surfaces regressions (new vulns, newly-archived deps, scorecard drops crossing OSSF's 7.0 threshold, libyear growth on unchanged versions, Ruby newly EOL). Exits 1 if any regression is detected, 2 on a malformed or unsupported baseline.
- GitHub token cascade: discovers token from `--github-oauth-token`, `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token` in that order. GitLab cascade mirrors it (`--gitlab-token`, `GITLAB_TOKEN`, `glab auth status --hostname=gitlab.com --show-token`). Eliminates the "why am I rate limited?" friction on local runs when `gh`/`glab` are already authed.
- JSON output gains `schema_version`, `tool`, and `generated_at` keys on top of the existing `{gems, ruby}` envelope (shipped since 1.1). Purely additive — existing consumers reading `payload["gems"][name]` continue to work. See `docs/schema.md`.

## [1.3.0] - 2026-04-08

### Changed

- **BREAKING:** Bump minimum Ruby version to 3.3 (3.2 is EOL); transitive dependencies (e.g. `io-event`) now require Ruby >= 3.3

## [1.2.1] - 2026-02-20

### Fixed

- Ruby version freshness reported the running Ruby (e.g. 4.0.1) instead of the target project's Ruby from `Gemfile.lock`; now reads `RUBY VERSION` section from lockfile, falls back to running version only when absent
- Platform-specific gems (e.g. `nokogiri` on multiple architectures) were processed once per platform, wasting API calls and inflating the progress counter total

## [1.2.0] - 2026-02-20

### Added

- `--fail-if-vulnerable[=SEVERITY]` flag: exit 1 if any gem has known vulnerabilities, optionally filtered by severity (low/medium/high/critical)
- `--fail-if-outdated=LIBYEARS` flag: exit 1 if any gem exceeds the given libyear threshold
- Coloured OpenSSF column in terminal output: green for strong practices (7.0+), yellow for notably weak (below 4.0)

### Changed

- Removed composite health score (0-100) and Health column from terminal, markdown, and JSON output; individual columns (vulns, OpenSSF, activity, version) communicate these signals without collapsing them into one number
- Replaced `--fail-below-score` with `--fail-if-vulnerable` and `--fail-if-outdated` for targeted CI gating

### Fixed

- Repository URLs with `.git` suffix (e.g. `socketry/async.git`) caused 404s against GitHub/GitLab APIs
- GitLab 301 redirects for renamed projects silently failed; now follows up to 3 redirects with trusted host check
- Network errors (`ECONNRESET`, timeouts, etc.) during RubyGems version lookup or HTTP API calls dropped the entire gem from results instead of warning
- GitHub Packages URI check used substring match, allowing crafted URLs to bypass host validation; now parses URI and compares host exactly
- Tri-state `archived?` predicate renamed to `archived` to honestly reflect `true`/`false`/`nil` return contract
- Rubocop offences from code scanning (WordArray, IfInsideElse, MultilineHash, frozen_string_literal)

## [1.1.0] - 2026-02-20

### Added

- `--ignore=GEM,GEM2,...` flag to exclude gems from pass/fail checks while keeping them in output
- `--fail-below-score=SCORE` flag for health-based CI gating (exit 1 if any gem scores below threshold)
- Yanked version detection: flags pinned versions that have been pulled from RubyGems
- Archived repo detection via GitHub and GitLab APIs, treated as critical for exit checks
- Libyear metric: years between installed and latest release per gem, total in summary
- Advisory enrichment: CVSS scores, titles, and IDs from deps.dev per vulnerability
- Composite health score (0-100) combining version freshness, activity, OpenSSF Scorecard, and vulnerabilities
- Health column in terminal and markdown output, system average in terminal summary
- Ruby version freshness: reports current Ruby version, EOL status, and libyear behind latest via endoflife.date API
- Source detection: identifies gem source type (rubygems, git, path) from Bundler lockfile
- Non-rubygems gem handling: git/path-sourced gems show gracefully with source indicator instead of failing silently
- GitHub Packages registry support: fetches versions from `rubygems.pkg.github.com` using existing `--github-oauth-token` (requires `read:packages` scope)
- CVSS v2 fallback: older advisories without v3 scores now show severity using v2 scores from deps.dev

### Changed

- Vulnerability column shows count with highest severity label (e.g. "3 (critical)")
- Markdown vulnerability column shows advisory IDs
- Markdown table adds libyear and health columns
- Terminal summary includes libyear total and health average
- JSON output wrapped in `{ "gems": ..., "ruby": ... }` structure
- Version string validation guards against malformed versions from git-sourced gems
- Progress counter on stderr during gem checking so large Gemfiles don't appear frozen
- Actionable rate limit message when GitHub API quota is exhausted
- `--fail-below-score` now validates range (0-100) at parse time
- `--gems` option stores structured data from the start instead of mutating mid-run
- API failures (timeouts, HTTP errors, malformed responses) now warn on stderr instead of degrading silently
- Vulnerability count based on successfully fetched advisories so count and severity always agree

### Fixed

- Vulnerability counts now checked against installed version, not latest (was masking CVEs in older pinned versions)
- `GitlabClient.archived?` returned `false` on API failure instead of `nil`, incorrectly asserting repos were not archived
- `repo_archived?` rescued all `StandardError`, masking bugs; now catches only `Octokit::Error` and `Faraday::Error`
- `last_commit_date` had no error handling; any failure dropped the entire gem from results
- Malformed date strings from GitHub/GitLab APIs no longer raise unhandled `ArgumentError`

## [1.0.2] - 2026-02-19

### Changed

- Reduce gem package from 2.4MB to essentials only (lib/, bin/still_active, LICENSE, README, CHANGELOG, gemspec)

## [1.0.1] - 2026-02-19

### Changed

- Rewrite gemspec summary and description for discoverability (mentions dependency health, outdated, vulnerabilities, abandoned gems)
- Restructure README: problem-first opening, terminal output example, comparison table vs bundle outdated/bundler-audit/libyear-bundler, quick start guide
- Add 13 GitHub topics for search visibility
- Update GitHub repo description

## [1.0.0] - 2026-02-19

### Added

- `--fail-if-critical` and `--fail-if-warning` flags for CI quality gating
- deps.dev integration: OpenSSF Scorecard scores and known CVEs in output
- Autopublish to RubyGems via GitHub Releases (trusted publishing)
- Coloured terminal table as default output format with summary line
- Auto-detection: terminal output for TTY, JSON when piped
- GitLab repository support with `--gitlab-token` flag
- Default token loading from `GITHUB_TOKEN` and `GITLAB_TOKEN` env vars
- Dependabot for bundler and GitHub Actions (grouped minor/patch updates)
- Require MFA for RubyGems publishing

### Changed

- **BREAKING:** Rename `--no-warning-range-end` to `--safe-range-end` (fixes OptionParser conflict)
- **BREAKING:** Default output is now auto-detected (terminal on TTY, JSON when piped); `--markdown` is an explicit opt-in
- **BREAKING:** Markdown table collapsed from 12 to 9 columns (dates inlined with versions)
- Replace `activesupport` with lightweight `CoreExt` refinement
- Remove unused `async-http` dependency (82 -> 66 installed gems)
- **BREAKING:** Bump minimum Ruby version to 3.2 (3.1 is EOL)
- Rename "Scorecard" column to "OpenSSF" for clarity
- Extract shared HTTP helper from DepsDevClient and GitlabClient
- Consolidate VCR test configuration into spec_helper
- Re-record VCR cassettes against live APIs

### Fixed

- Markdown output showed wrong emoji for pre-release version comparison
- Errors during gem lookup now go to stderr instead of corrupting structured output
- Repository URL matching handles dots in org/repo names
- Guard against nil URLs in Repository.valid?
- Handle malformed JSON responses from APIs gracefully
- Terminal output no longer crashes on empty results
- Version comparison uses `Gem::Version` instead of string equality
- deps.dev project ID parsing handles URLs with trailing paths
- Add `faraday-retry` runtime dependency to silence Faraday v2 warning
- Add missing `require "time"` for `Time.parse` in VersionHelper
- Fix `:last_activity_warning_emoji` key typo
- Remove dead `Gemfile` module and unused `include VersionHelper`

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
