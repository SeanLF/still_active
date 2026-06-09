# AGENTS.md

still_active flags dependencies that look unmaintained (stale releases, archived
repos, advisories) and suggests alternatives. It's the correlation layer over the
dependency ecosystem, not a replacement for bundler-audit, `bundle outdated`, or
libyear. Compose those; don't reimplement them.

## Commands

- Setup: `bin/setup` (installs deps, wires git hooks)
- Test + lint: `rake` (full suite). `rake spec` or `rake rubocop` for one.
- Run: `bundle exec still_active` (try `--json`, `--sarif`, `--alternatives`)
- Console: `bin/console`
- `rake` must pass before a commit.

## Conventions

- Ruby community idioms: `it`, `_1`, shorthand hash, `tap`/`then`. Exceptions over
  monads. Avoid metaprogramming.
- Compose, don't reimplement: lean on bundler-audit, deps.dev, ruby-advisory-db
  rather than rebuilding their checks.
- Credentials only go to a host the user opted into, never one derived from
  lockfile input. A gem source URL in a lockfile is untrusted.
- New integrations are providers, in their own file. A provider fills one or both
  roles: version source (where `.gem` versions come from) or repo signals
  (`archived?`, last commit). See `gitlab_client.rb`, `artifactory_client.rb`;
  GitHub extraction is tracked in #30.
- Tests first. Stub HTTP with WebMock; no live network in specs.

## Dependencies

Every line of code and every dependency is a liability. Before adding a gem, check
whether stdlib or something already in the bundle does the job.

When you do add a runtime dependency, declare its real minimum version in the
gemspec (`>= x.y`), not whatever you happen to have installed. Find the lowest
version that still passes the suite; don't pin high out of caution. The `floors` CI
job runs the suite against `Gemfile.floors` (every declared floor, pinned). Red
means a floor is too low and needs bumping.

## House style (prose, docs, comments, commits)

- No em dashes. Commas, semicolons, periods, or restructure.
- Conventional commits, no emoji, explain why not what.

## AI assistance

Welcome, and a lot of this project uses it. Same bar as any work: you own the
output, you ran it, claims are checked against the source not memory. See
CONTRIBUTING.md.
