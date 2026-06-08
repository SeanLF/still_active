# Alternative-gem leads (issue #28) — design

## Summary

When still_active flags a gem as abandoned (GitHub-archived or critically stale),
optionally surface up to three **maintained alternatives** drawn from the Ruby
Toolbox catalog, ranked by adoption. They are presented as *leads to verify*,
not vetted recommendations, and the feature is silent when the catalog has no
entry for the gem.

The feature is **opt-in** (`--alternatives`). When it is off but a gem would
have qualified, print a one-line discoverability hint instead of fetching
anything.

## Motivation

Ruby has no native way for a gem author to say "this is dead, use X":

- **npm** (`npm deprecate`), **Go** (`// Deprecated:` in go.mod), and **NuGet**
  (deprecated + structured alternate-package) all let authors declare a successor.
- **RustSec** curates `informational = "unmaintained"` advisories that point to
  alternatives; `cargo-audit` surfaces them as warnings, not hard errors.
- **Ruby** has neither: `Gem::Deprecate` is method-level only, and
  `ruby-advisory-db` (which still_active already consumes) is vulnerability-only.

So still_active fills a real double gap. Because our signal is a *heuristic*
(same Ruby Toolbox category != drop-in replacement), not author- or
curator-declared, we are the lowest-confidence tier and must hedge accordingly —
hence "leads, verify with your tooling" and a non-failing, opt-in treatment
(the same posture RustSec/cargo-audit take for unmaintained crates).

PoC evidence (see `scratch/poc_*.rb`): on verified-archived gems the catalog
covers ~70% and yields good live alternatives (paperclip -> carrierwave/shrine,
cancan -> pundit/cancancan, debugger -> byebug/debug). Coverage on full lockfiles
is ~30-40%, so silence-on-miss is the common case and must be graceful.

## Components

### `CatalogIndex` (new) — gem -> categories

- Public API: `siblings_for(gem_name) -> [String]`, `categories_for(gem_name) -> [{permalink:, name:}]`.
- Source: the `rubytoolbox/catalog` repo tarball, fetched via the existing
  `octokit` client — `archive_link("rubytoolbox/catalog", format: "tarball", ref: "main")`
  then `URI.open` (follows the codeload redirect). Parsed with stdlib
  `Zlib::GzipReader` + `Gem::Package::TarReader` + `YAML.safe_load`. Each
  `catalog/<group>/<category>.yml` contributes its `projects:` to the reverse
  index; the category `name:` is kept for display. GitHub-slug projects
  (`owner/repo`) are indexed by their tail. (Verified: 46 KB tarball, 2941 gems.)
- Cache: the *built* index is written to
  `${XDG_CACHE_HOME:-~/.cache}/still_active/catalog-index.json` with a ~7-day TTL
  (mtime check). Fresh cache hit -> no network. Catalog moves slowly, so this is
  safe; CI runs pay one fetch per cold environment.
- Best-effort: any fetch/parse/cache error logs a warning to stderr and yields an
  empty index. The feature degrades to silent; the audit is never blocked.

### `AlternativesHelper` (new) — ranked leads

- `leads_for(gem_name, index:) -> [String]` (top 3).
- `index.siblings_for(gem_name)` minus the gem itself; empty -> `[]` (silent).
- Restrict to rubygems-named siblings (drop `owner/repo` slugs, which we can't
  rank by downloads). Fetch each sibling's total downloads via the existing
  `gems` dependency — `Gems.info(name)["downloads"]` (verified). Bound the number
  of siblings considered so a large category can't explode the call count.
  Return the top 3 by downloads.
- Best-effort: a failed `Gems.info` drops that sibling, not the feature.

### Workflow integration (`lib/still_active/workflow.rb`)

- Load `CatalogIndex` once before the fan-out, mirroring how `advisory_db` is
  loaded at `workflow.rb:24`, and pass it into `gem_info`.
- After a gem's result hash is assembled, if `config.alternatives` is set and
  `ActivityHelper.activity_level(result) in [:archived, :critical]`, set
  `result[gem_name][:alternatives] = AlternativesHelper.leads_for(gem_name, index:)`.
  Sibling-download fetches run inside the existing async task, so they
  parallelize across gems.

### Config / CLI (`config.rb`, `options.rb`, `cli.rb`)

- New `--alternatives` flag -> `config.alternatives` (default `false`).
- Discoverability: when a gem is `:archived`/`:critical` and `config.alternatives`
  is false, the human-facing formatters print a single hint line
  ("run with `--alternatives` for maintained replacements") — no fetch performed.

### Output (only where it fits)

- **Terminal** (`terminal_helper`): a sub-line under flagged rows —
  `↳ leads (Ruby Toolbox): carrierwave · shrine · kt-paperclip — verify fit`.
- **Markdown** (`markdown_helper`): an inline "Alternatives" note on flagged rows.
- **JSON**: `alternatives: [...]` on the gem entry (already serialized from the
  result hash — the agent-consumable surface).
- **SARIF** (`sarif/rules.rb`): fill the existing "consider a maintained
  alternative" help text with the actual names for the archived/stale finding.
- **CycloneDX**: skipped — it is a bill-of-materials, not advice.

Each surface renders only when `:alternatives` is present and non-empty.

## Failure handling

Every part of this feature is best-effort and must never crash, corrupt, or
materially slow the primary audit:

- Catalog fetch/parse/cache failure -> empty index -> silent.
- `Gems.info` failure for a sibling -> that sibling dropped.
- Sibling fetches are bounded to cap added latency/calls.
- Nothing here participates in `--fail-if-*` exit codes.

## Testing

- VCR cassettes for the catalog tarball fetch and the rubygems downloads calls.
- `CatalogIndex`: tarball parse -> index shape; cache write/read + TTL expiry;
  fetch failure -> empty (silent).
- `AlternativesHelper`: ranking by downloads, top-3 cap, slug filtering,
  silent-on-no-siblings, `Gems.info` failure tolerance.
- Workflow: alternatives set only when `config.alternatives` and level in
  `[:archived, :critical]`; not set otherwise.
- Each output format: leads rendered when present, hint shown when flag off,
  nothing shown for healthy gems / catalog misses.

## Out of scope (v1)

- Per-sibling liveness filtering (downloads-only ranking; a popular-but-dead
  sibling is a small, accepted risk — add a "released within N years" guard as a
  fast-follow if it shows up).
- CycloneDX output.
- Any vendored snapshot or scheduled-refresh job (runtime fetch + cache covers it).

## Future: authoritative successor source

[rubygems/rubygems.org#4678](https://github.com/rubygems/rubygems.org/issues/4678)
("mark gems as no longer maintained") is open but scoped to an unmaintained flag
plus install-time warnings — it does **not** include a recommended-successor
field. If Ruby ever gains an author-declared successor (the npm/Go/NuGet
capability), it would be higher-confidence than our heuristic and should be
preferred ahead of catalog leads. `AlternativesHelper` should be shaped so an
authoritative source can slot in front of the catalog without reworking callers.
Worth a comment on #4678 advocating the successor field (separately from this
feature).
