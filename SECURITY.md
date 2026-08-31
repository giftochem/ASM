# Security Policy

## Purpose of this project

ASM (Attack Surface Mapper) is a defensive security tool intended for
**authorized** attack-surface discovery and continuous monitoring. It is
built for organizations mapping and monitoring their own external
footprint, and for security practitioners operating under an explicit
engagement (e.g. a signed penetration-testing or MSSP contract).

Every scan and discovery operation in ASM is gated behind an explicit,
per-asset `authorization_confirmed` flag — see the README's "Authorization
& scope disclaimer" section for the full enforcement model. **You must have
verifiable, explicit authorization before using ASM against any asset you do
not own.** Scanning systems without authorization may violate the Computer
Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent
computer-crime laws in other jurisdictions, regardless of intent.

## Reporting a vulnerability in ASM itself

If you discover a security vulnerability in ASM's own code (as opposed to
misuse of ASM against an unauthorized target), please report it privately
rather than opening a public issue or pull request that discloses it.

A dedicated security contact address has not yet been configured for this
project. Until one is published here, please open a private security report
through the repository's available private vulnerability reporting
mechanism, rather than filing a public issue.

Please include, where possible:
- A description of the vulnerability and its potential impact
- Steps to reproduce (or a proof of concept)
- The affected version/commit

## Scope

This policy covers vulnerabilities in ASM's own codebase (backend, frontend,
Docker/deployment configuration, and CI). It does not cover vulnerabilities
in third-party dependencies — please report those to the relevant upstream
project — though we welcome a heads-up if a dependency issue materially
affects ASM.
