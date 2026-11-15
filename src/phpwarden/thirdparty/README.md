# Trivy import: the non-PHP parts of a PHP project

phpwarden covers PHP: the engine, Composer, WordPress, and your own code. The other
things a PHP project ships are Trivy's job: `package-lock.json` / `yarn.lock`, the
container image, the OS packages in it, and the Dockerfile, Terraform and Kubernetes
files next to it. phpwarden does not reimplement Trivy. It reads Trivy's JSON and
puts those findings in the same ranked report.

## Commands

    trivy fs --format json --output trivy.json .          # npm, IaC, secrets
    trivy image --format json --output image.json IMAGE   # OS packages in the image

    phpwarden trivy-import trivy.json image.json --kev known_exploited_vulnerabilities.json --epss epss_scores-current.csv.gz
    phpwarden assess . --trivy trivy.json --trivy image.json --kev kev.json --epss epss.csv
    phpwarden assess . --run-trivy        # runs `trivy fs` only if trivy is already on PATH
    phpwarden assess . --trivy trivy.json --baseline before.json   # fixed / not re-checked covers Trivy items
    phpwarden trivy-import trivy.json --report-to URL --report-token T     # dashboard, source "Trivy"

## How findings are ranked

The order is CISA KEV first, then EPSS, then severity, the same as for PHP findings.
KEV and EPSS data for non-PHP CVEs comes from the files you pass with `--kev` (the
CISA catalogue JSON) and `--epss` (the FIRST CSV, which may be gzipped). Without
them the report says it ranked by severity only.

In `assess`, the tiers are:

- KEV or EPSS ≥ 0.5: act now.
- Critical or high: this week.
- Medium: scheduled.
- Everything else: watch.

Development dependencies (Trivy's `Dev` flag) are capped at this week. A secret is
act now when it is critical or high, and this week otherwise.

## What it does not do

- Composer results inside a Trivy report are skipped, because `phpwarden deps` already
  covers them with reachability.
- Secrets are reported by rule, file and line only. Trivy's `Match` and `Code` fields
  are never read, stored, printed or uploaded.
- phpwarden never downloads or installs Trivy. Trivy (Apache-2.0, by Aqua Security) is
  a separate tool you install and run yourself.
- On the dashboard, exploited-CVE alerts for a stored Trivy finding fire when the
  phpwarden feed's exploited list contains that CVE. That list is PHP-focused. For
  other CVEs, the alert comes from the `known_exploited` flag at upload time, which
  needs `--kev`.

Schema: Trivy JSON report, SchemaVersion 2.
