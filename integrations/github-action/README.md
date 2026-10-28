# phpwarden GitHub Action

The action moved to its own repository so it can be listed on the GitHub
Marketplace and versioned independently of the CLI:

**https://github.com/primeagent001-bot/phpwarden-action**

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: primeagent001-bot/phpwarden-action@v1
    with:
      fail-on: exploited
```

It scans `composer.lock`, WordPress installs and a production PHP engine
version; writes a job summary, `composer.lock` line annotations and SARIF;
and can report to your phpwarden dashboard. See that repo's README for inputs
and outputs.

The `action.yml` that used to live here is gone — `uses: …/phpwarden/integrations/github-action`
references must be updated to the new path.
