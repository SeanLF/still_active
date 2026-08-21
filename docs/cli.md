# CLI reference

Every flag is optional. This block is the tool's own `--help` output, kept in sync with the option parser by a test.

```text
Usage: still_active [options]

        all flags are optional

        --gemfile=GEMFILE            path to gemfile
        --gems=GEM,GEM2,...          Gem(s)
        --sbom=PATH                  audit a CycloneDX SBOM cross-ecosystem (npm/pypi/cargo/go/maven/nuget); JSON output
        --terminal                   Coloured terminal output (default in TTY)
        --markdown                   Markdown table output
        --json                       JSON output (default when piped)
        --alternatives               Suggest maintained alternatives (Ruby Toolbox leads) for archived/critical gems
        --unreleased-commits         Count commits on the default branch since the latest release (GitHub only; opt-in)
        --direct-only                Audit only direct (declared) deps, not the full transitive graph
        --sarif[=PATH]               SARIF 2.1.0 output for GitHub Code Scanning
        --cyclonedx[=PATH]           CycloneDX SBOM output (stdout, or a file path)
        --cyclonedx-version=VERSION  CycloneDX spec version: 1.6 (default) or 1.7
        --baseline=PATH              Compare current state to baseline JSON; emit markdown deltas
        --github-oauth-token=TOKEN   GitHub OAuth token to make API calls
        --gitlab-token=TOKEN         GitLab personal access token for API calls
        --artifactory-token=TOKEN    Artifactory token for private gem registry API calls
        --artifactory-host=HOST      Artifactory host allowed to receive the global token (e.g. my-org.jfrog.io)
        --ecosystems-email=EMAIL     Contact email to join the ecosyste.ms polite pool (higher rate limit)
        --simultaneous-requests=QTY  Number of simultaneous requests made
        --safe-range-end=YEARS       maximum years since last release considered safe, no warning (default 1.5)
        --warning-range-end=YEARS    maximum years since last release that triggers a warning, beyond this is critical (default 3)
        --fail-if-critical           Exit 1 if any gem has critical activity warning
        --fail-if-deprecated         Exit 1 if any dependency's maintainer has deprecated it
        --fail-if-warning            Exit 1 if any gem has warning or critical activity warning
        --fail-if-vulnerable[=SEVERITY]
                                     Exit 1 if any gem has vulnerabilities (optionally at or above SEVERITY)
        --fail-if-outdated=LIBYEARS  Exit 1 if any gem exceeds LIBYEARS behind latest
        --fail-if-poison[=TIER]      Exit 1 on a poison-pill at or above TIER (note|warning|critical; default warning)
        --fail-if-language-ceiling[=TIER]
                                     Exit 1 on a language-runtime ceiling (Ruby/Python; default: EOL-forced only; =note also gates latest-not-yet)
        --ignore=GEM,GEM2,...        Exclude gems from pass/fail checks (still shown in output)
        --critical-warning-emoji=EMOJI
        --futurist-emoji=EMOJI
        --success-emoji=EMOJI
        --unsure-emoji=EMOJI
        --warning-emoji=EMOJI
    -h, --help                       Show this message
    -v, --version                    Show version
```

## See also

- [Authentication](authentication.md): tokens for GitHub / GitLab / Codeberg / Artifactory
- [Configuration](configuration.md): the `.still_active.yml` policy file, activity thresholds, transitive-dependency behaviour
- [CI integration](ci.md): SARIF, the GitHub Action, composing with `dependency-review-action`
- [Rules](rules.md): the SA001-SA009 finding catalog
- [JSON schema](schema.md): the `--json` output contract
