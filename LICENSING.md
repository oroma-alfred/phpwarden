# Licensing

phpwarden is **open-core**: the scanner engine is open source, the hosted
service and maintained feed are commercial. This mirrors how comparable tools
are licensed (Snyk CLI, Trivy, Grype, Semgrep, OWASP Dependency-Check all use
Apache-2.0 for the scanner and keep the data feed / platform proprietary).

## Apache License 2.0 — open source

Covered by [`LICENSE`](LICENSE) (Apache-2.0):

| Path | What it is |
|------|------------|
| `src/phpwarden/` | The engine: CLI + library (scan, deps, wordpress, integrity, detect, rules, probe, code, assess, report, feed) |
| `src/phpwarden/data/` | The **bundled community** vulnerability feed |
| `integrations/` | The GitHub Action and other integrations |
| `tests/` | The test suite |

You may use, modify, and redistribute these freely under the terms of the
Apache License, Version 2.0, including commercially.

## Proprietary — commercial

**Not** covered by the Apache License:

| Path / thing | Terms |
|--------------|-------|
| `saas/` | [`saas/LICENSE.txt`](saas/LICENSE.txt) — proprietary |
| `server/` | [`server/LICENSE.txt`](server/LICENSE.txt) — proprietary |
| The **maintained** feed (rebuilt twice a day) | Delivered to paying subscribers; not redistributable |
| The hosted service at phpwarden.io / app.phpwarden.io | Commercial, subject to its terms of service |

The engine runs fully offline on the bundled community feed with no license,
and `phpwarden feed update` pulls a free weekly snapshot of the feed with no
key. A one-project dashboard is free. Paid plans add the maintained feed
(rebuilt twice a day), more projects, weekly live checks, history, alerts and
outbound webhooks.

Questions about commercial use or redistribution: open an issue or email
sales@phpwarden.io.
