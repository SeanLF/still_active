# Poison-pill receipt rendering (PR-C) — design

Status: designed 2026-07-01. Follows PR-B (signal shipped in JSON: `constraints:
[{dependency, requirement, dep_latest, majors_behind, kind}]` + `poison:` boolean
on `gem_data`, native + cross-ecosystem). This PR surfaces that data in the
human-facing terminal and markdown outputs.

## Goal

Make a poison gem's receipt visible where a human reads output. The value is the
actionable finding ("this dead gem blocks your upgrades"), so rendering shows the
*worst offenders + how many*, not an enumeration of every cap.

## Decisions (settled)

- **Annotation only, not a lifecycle status.** Poison is a different axis from the
  maintenance lifecycle (`:dead`…`:ok` = "is it maintained?"; poison = "does this
  dormant dep block *my* upgrades?"). A gem can be `:legacy` *and* poison.
  `StatusHelper.gem_status` / `project_status` are **unchanged**. `--fail-if-poison`
  (a future PR) gates on the `poison:` boolean directly.
- **Only `poison == true` gems render.** Pure exact-pin gems (`constraints` present,
  `poison: false`) keep their data in JSON but are not rendered here — keeps the
  headline crisp. Exact-pin caps still appear *inside* a poison gem's receipt when
  that gem mixes ceilings and pins.
- **Top-3 + total, both surfaces.** Listing all caps adds length, not decision
  value: the action is "remove the one dead gem," not "fix N caps." The full list
  stays in JSON. Terminal and markdown use the same selection; markdown formats each
  shown cap slightly richer.
- **Deterministic order:** `majors_behind` desc, then `dependency` name asc (stable
  for the baseline diff).
- **Native path only.** `run_sbom` is JSON-only (no TerminalHelper/MarkdownHelper
  path exists for `--sbom`), so cross-ecosystem poison is already fully surfaced in
  the `--sbom` JSON. Nothing to add there.

## Components

### 1. Selection helper — `ConstraintHelper.top_findings(constraints, limit: 3)`

Lives next to `poison_findings` / `POISON_KINDS` (same owner, no new file). Pure.

```
top_findings(constraints, limit: 3) # =>
  { shown: [<=limit constraint hashes, worst-first], total: constraints.length }
```

Order: `sort_by { [-majors_behind, dependency] }`, take `limit`. `total` is the full
count so a renderer can print "— N total" / "+K more". Both renderers call this so
the selection can't drift (the "computed two ways" trap the codebase avoids).

### 2. Terminal — `TerminalHelper`

A yellow `↳` sub-line per poison gem. Yellow (not the dim used for
alternatives/transitive hints) because it's an actionable finding; the gem's row is
already red (poison requires `:critical`/`:archived`), so poison is never on a green
row and the yellow sub-line explains the red without diluting red (reserved for
vulns/yanked/archived).

- Single cap: `  ↳ poison: caps activemodel < 5.0 (4 majors behind, latest 8.x)`
- Multi cap: `  ↳ poison: caps chalk (4 behind), through2 (3), vinyl (3) +11 more`
- Transitive: `  ↳ poison (via rails): caps …` — and the generic
  `dependency_path_line` is **suppressed** for this gem (the poison line subsumes it).

Wiring in `render`: the current single `extra` (`direct == false ? path :
alternatives`) becomes an ordered list. For a poison gem, emit the poison line first;
skip the generic transitive line; still emit the alternatives line if a direct poison
gem has alternatives (two sub-lines, different actions — acceptable and rare). For a
non-poison gem, behavior is unchanged.

Summary line: append `· N poison-pills` (yellow) when `N > 0`, where N counts
`poison == true` gems. Placed after the vulnerabilities part.

New private methods: `poison_line(data)`, `poison_receipt(constraints)` (shared
phrasing built from `top_findings`), and a `poison_count(result)` for the summary.

### 3. Markdown — `MarkdownHelper.poison_section(result)`

Consistent with `alternatives_section` / `transitive_section`. Selects
`poison == true` gems; `""` when none. Wired in `cli.rb#render_markdown` next to the
other sections (`puts poison_section unless empty`).

```
**Poison-pill findings** (dormant deps capping your tree below its latest major):
- `gulp-util` caps `chalk` `^1.0.0` (4 majors behind, latest 5.x), `through2` `^2.0.0` (3), `vinyl` `^0.5.0` (3) — 14 total
- `protected_attributes` caps `activemodel` `< 5.0` (4 behind, latest 8.x)
```

Transitive gems get `via \`rails\`` after the gem name. Names/requirements go through
`MarkdownEscape` (code spans), matching the existing sections.

## What "latest 8.x" means

`dep_latest` (e.g. `8.0.1`) abbreviated to its major + `.x` (`8.x`) — the cap is a
major-level gap, so the major is the honest granularity. Shown only in the single-cap
terminal case and per-cap in markdown; multi-cap terminal drops it for space (the
`(N behind)` carries the gap).

## Testing (pure, no network)

- `ConstraintHelper.top_findings`: worst-first order, tie-break by name, `limit`,
  `total`, empty input.
- `TerminalHelper`: poison sub-line present for a poison gem (ANSI-stripped substring
  checks, per existing spec style); single vs multi-cap phrasing; transitive fold +
  suppression of the generic transitive line; summary `N poison-pills`; a non-poison
  dormant gem gets no poison line.
- `MarkdownHelper.poison_section`: bullet content, top-3 + total, transitive "via",
  escaping, `""` when no poison gems.
- `cli.rb#render_markdown`: section emitted when present (or cover via helper spec +
  a thin integration check).

## Out of scope (later)

`--fail-if-poison` gate; SARIF poison result; lifecycle `:poison` status;
cross-ecosystem terminal/markdown (blocked on `--sbom` having no human renderer at
all — a separate, larger piece).
