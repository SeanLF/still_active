# Security Policy

## Reporting a vulnerability

Please report security issues privately, not as a public issue or PR.

Use GitHub's private vulnerability reporting (the "Report a vulnerability" button on
the Security tab), or email contact@seanfloyd.dev.

still_active runs against lockfiles and gem metadata from repositories you may have
just cloned, and it can hold registry credentials. Credential handling, network
calls to lockfile-derived hosts, and parsing of untrusted input (gem names, source
URLs) are all in scope.

Expect an acknowledgement within a few days. Please allow a reasonable window to
ship a fix before public disclosure.
