# phpwarden GitHub Action

Scan `composer.lock`, a WordPress install and your production PHP version on
every push, with findings ranked by real-world exploitation — CISA KEV first,
then EPSS, then CVSS. Of about 19,500 PHP vulnerabilities in the feed, 54 are
known to be exploited (CISA KEV, as of 2026-11-14); `fail-on: exploited` breaks the
build on those and nothing else.

The action lives in its own repository so it can be listed on the GitHub
Marketplace and versioned independently of the CLI:

**https://github.com/oroma-alfred/phpwarden-action**

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: oroma-alfred/phpwarden-action@v1
    with:
      fail-on: exploited      # or: critical | high | medium | exposed (default) | never
      report-url: https://app.phpwarden.io/v1/reports
      report-token: ${{ secrets.PHPWARDEN_TOKEN }}
```

It writes a job-summary table, annotates vulnerable lines in `composer.lock`,
can upload SARIF to the Security tab (`upload-sarif: "true"`), and — when
`report-url`/`report-token` are set — posts results to the
[phpwarden dashboard](https://app.phpwarden.io) for history across repos and
alerts when a finding you carry lands in KEV. See that repo's README for all
inputs and outputs.

Outside Actions, the same thing from a shell is:

```bash
phpwarden deps composer.lock --report-to https://app.phpwarden.io/v1/reports --report-token <token>
```

The `action.yml` that used to live here is gone — `uses: …/phpwarden/integrations/github-action`
references must be updated to the new path.
