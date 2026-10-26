# phpwarden GitHub Action

Scan PHP/Composer/WordPress in CI, fail the build on exploited vulnerabilities,
and report results to your phpwarden dashboard.

## Quick use

Add `.github/workflows/phpwarden.yml` to your repo:

```yaml
name: phpwarden
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: localprime/phpwarden/integrations/github-action@v2
        with:
          composer-lock: composer.lock
          report-url: https://app.phpwarden.io/v1/reports
          report-token: ${{ secrets.PHPWARDEN_TOKEN }}
```

Store the project ingest token (from your dashboard) as the `PHPWARDEN_TOKEN`
repo secret. The build fails if a vulnerable component is found; set
`fail-on: never` to report without failing.

## What it does

1. Installs the `phpwarden` CLI (zero dependencies).
2. Runs `deps` on your `composer.lock` and, if set, `wordpress` on a path.
3. Posts findings to your dashboard (history + alerts) when `report-url` is set.
4. Fails the job when exposed, so a vulnerable dependency blocks the merge.

Inputs: `composer-lock`, `wordpress-path`, `report-url`, `report-token`,
`fail-on` (`exposed` | `never`).
