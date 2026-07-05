# Authentication

`still_active` reads repository signals (archived status, last commit) from the forge that hosts each dependency, and package metadata from gem registries. Most public audits need no token at all; the sections below cover when and how to provide one.

## GitHub

Token discovery order:

1. `--github-oauth-token=TOKEN` CLI flag
2. `GITHUB_TOKEN` environment variable (CI convention)
3. `GH_TOKEN` environment variable (`gh` CLI convention)
4. `gh auth token` (if `gh` is installed and authenticated)

With a token, GitHub repo signals come from the GitHub API (5000 requests/hour). On a near-reset rate-limit response (within ~60 seconds, typically a secondary/burst limit the concurrent fan-out can trip even with a token), `still_active` waits it out and retries rather than dropping that gem's signals; a far-off reset (the hourly limit is exhausted) is not waited out, so run less often.

**Without a token**, the unauthenticated GitHub API is capped at 60 requests/hour, unusable past a handful of gems, so `still_active` falls back to [ecosyste.ms](https://ecosyste.ms) for GitHub repo signals (5000 anonymous requests/hour). This keeps a large `Gemfile` working with no token at all. The fallback is GitHub-only: ecosyste.ms doesn't track commit recency for GitLab/Codeberg, so those hosts report `unknown` unauthenticated. A token still gives the freshest data and unlocks `--unreleased-commits`, so prefer one in CI.

To be a good citizen of the free ecosyste.ms service, join its "polite pool" (a higher rate limit) by passing a contact email via `--ecosystems-email=you@example.com` or `STILL_ACTIVE_ECOSYSTEMS_EMAIL`. Optional, since the anonymous limit already covers a typical lockfile.

## GitLab

Cascade mirrors GitHub: `--gitlab-token` → `GITLAB_TOKEN` → `glab auth status --show-token`. Optional for public repos, required for private ones.

## Forgejo / Codeberg

The rare gem whose canonical `source_code_uri` is `codeberg.org` is read anonymously by default. Set `STILL_ACTIVE_FORGEJO_TOKEN` (or `CODEBERG_TOKEN`) only to raise the rate limit or reach a private repo. There is no CLI flag, since Codeberg has no ubiquitous CLI to borrow a token from the way `gh`/`glab` do.

## Artifactory (private gem registries)

`still_active` looks for Bundler's stored credentials first, so a private registry already configured in Bundler works with no extra setup:

```bash
bundle config set credentials.my-org.jfrog.io user:pass
```

If none are set there, it falls back to a token from `--artifactory-token` or `STILL_ACTIVE_ARTIFACTORY_TOKEN`. A `user:password` value is used for Basic auth; anything else is treated as a bare token for Bearer auth. Valid authentication is required for private JFrog gem registries (`*.jfrog.io`).

When providing the token via flag or env, you **must** also set `--artifactory-host` or `STILL_ACTIVE_ARTIFACTORY_HOST` to the expected hostname (e.g. `my-org.jfrog.io`). `still_active` sends the credentials only to that host, so a lockfile that references other Artifactory hosts can't leak the token. This covers a single host; for multiple hosts, use Bundler's per-host credential configuration.
