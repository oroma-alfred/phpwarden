# Security policy

phpwarden is a security tool, so we hold ourselves to the standard we scan others against.
Thank you for helping keep it honest.

## Reporting a vulnerability

**Email: security@phpwarden.io** — please do not open a public GitHub issue for anything that
could be a vulnerability.

Include what you can: affected component and version, steps to reproduce, impact as you
understand it, and whether you have a suggested fix. Plain text is fine; a PGP key will be
published here once available.

What to expect from us:

| Step | Target |
|---|---|
| Acknowledgement | within 2 business days |
| Initial triage and severity | within 7 days |
| Fix or mitigation plan communicated | within 14 days for high/critical, 30 days otherwise |
| Public disclosure | coordinated with you; we credit reporters who want credit |

If you don't hear back in those windows, email again with `[overdue]` in the subject — it's a
miss on our side, not a brush-off.

## Scope

- The `phpwarden` CLI and `phpwarden-guard` daemon (`src/phpwarden/`, published to PyPI)
- The feed builder (`feedbuilder/`) and the published vulnerability feed
- The hosted dashboard and ingest API at `app.phpwarden.io`
- The Composer packages `phpwarden/phpwarden` and `phpwarden/laravel`
- The GitHub Action `oroma-alfred/phpwarden-action`

Out of scope: denial-of-service, volumetric or rate-limit testing against the hosted service;
anything that requires physical access or social engineering; findings in third-party
services we depend on (report those upstream, but tell us too).

## Safe harbor

Good-faith security research against the scope above is welcome. We will not pursue legal
action against researchers who: avoid privacy violations, data destruction and service
disruption; only access accounts and data they own or have explicit permission to test; stop
and report as soon as they confirm a vulnerability; and give us reasonable time to fix before
public disclosure. Testing against the hosted service should use your own account.

## Supported versions

| Version | Supported |
|---|---|
| 2.x (latest) | Yes |
| < 2.0 | No — please upgrade |

## Feed accuracy is a security issue too

A wrong "fixed version", a missed advisory, or a bad exploitation ranking can cause someone to
leave a vulnerable host unpatched. Report feed data errors to the same address, or — since
they're not sensitive — as a GitHub issue referencing the CVE and the source you believe is
correct. We treat these with the same priority as code bugs.

## How we treat our own findings

phpwarden reports what it can verify and labels uncertainty (`possibly exposed`, `claim=REFUSED`)
rather than overclaiming. If you find a case where it claims protection or exposure it cannot
actually substantiate, that is a bug we want to hear about.
