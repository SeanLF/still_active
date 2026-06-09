# Contributing

Issues and PRs both welcome. The project moves fast.

## Before you start

- For anything non-trivial, open an issue first so we can agree on the shape. Saves rework.
- `bin/setup` installs deps and wires the git hooks. `rake` runs the full lint +
  test suite (`rake spec` or `rake rubocop` for one). `bin/console` for a prompt.

## What makes a contribution land

The same bar for everyone, whoever (or whatever) wrote the first draft:

- **Verified**: you ran it the way a user would and confirmed it does what the
  description says. No version, compatibility, or behaviour asserted from memory.
- **Reproducible**: bug reports include steps that don't depend on your machine,
  plus Ruby and gem versions (`ruby -v`, relevant `bundle list` lines).
- **Prior art**: you checked how existing tools or the authoritative spec handle
  this before hand-rolling a heuristic.
- **Security**: if it touches credentials, network, or untrusted input (lockfiles,
  gem names), say what you considered.
- **Performance**: if it touches hot paths or adds network calls, note the cost.
- A PoC that shows the behaviour or the bug is the fastest path to merge.

## Dependencies

Every line of code and every dependency is a liability. Before adding a gem, check
whether stdlib or something already in the bundle does the job.

If you add a runtime dependency, declare its actual minimum supported version in
the gemspec, not the version you happen to have installed. Find the real floor (the
lowest that still passes the suite); the `floors` CI job verifies the gem works
against every declared floor, and goes red if one is too low.

## AI assistance

Welcome, and we use it here too. It doesn't change the bar above and it doesn't
lower your ownership: you ran it, you stand behind it. Disclosing that you used it
is appreciated, never penalized.

## Style

See AGENTS.md. No em dashes in prose; conventional commits, no emoji.
