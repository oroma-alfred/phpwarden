# open-pr mode (staged)

Draft of the `open-pr: true` input for the
[phpwarden GitHub Action](https://github.com/oroma-alfred/phpwarden-action).
It is not in the Marketplace action yet. `action-steps.yml` holds the input and
the step to merge into that repo's `action.yml` once the CLI release that ships
`phpwarden fix` is out.

What it does when `open-pr: "true"`:

1. `phpwarden fix composer.lock --only kev --packagist --apply --pr-body ...`
   runs Composer with the minimal bumps for CISA KEV findings only.
2. If `composer.lock` or `composer.json` changed, it commits them on a new
   branch and opens one pull request. The body lists each CVE with its KEV and
   EPSS status, plus the findings it left alone (major bump, conflict, no fix)
   and why.

Usage once released:

```yaml
permissions:
  contents: write
  pull-requests: write
steps:
  - uses: actions/checkout@v4
  - uses: shivammathur/setup-php@v2   # provides composer
  - uses: oroma-alfred/phpwarden-action@v1
    with:
      open-pr: "true"
```
