# Composer benchmark, November 2026

phpwarden vs `composer audit` vs OSV.dev on four PHP stacks pinned to old
releases, so all of them have known vulnerabilities:

| Stack | Pinned to |
|---|---|
| `laravel8` | laravel/framework 8.0.0, guzzlehttp/guzzle 7.0.1 |
| `symfony44` | symfony/symfony 4.4.0, twig/twig 2.12.0, doctrine/orm 2.7.0 |
| `drupal9` | drupal/core 9.0.0 (packages.drupal.org) |
| `libs` | guzzle 6.5.0, phpmailer 6.1.0, dompdf 0.8.3, phpseclib 2.0.20, league/commonmark 1.5.0, smarty 3.1.33, tcpdf 6.3.2, firebase/php-jwt 5.0.0 |

The lockfiles are committed, so every run scans the same package versions.

## Method

1. Run `composer audit --locked --format=json` and `phpwarden deps --json --no-reachability` on each lockfile, and query `api.osv.dev` for every locked package.
2. `compare.py` groups advisories per package: two findings are the same advisory when they share any identifier (CVE, GHSA, PKSA, FriendsOfPHP file, OSV aliases).
3. `reconcile.py` handles Drupal advisories that exist only as `SA-CORE-*` in Drupal's own repository and share no identifier with GHSA/OSV: one is paired with a finding from the other tools when their fixed releases match. Six were paired this way on 2026-11-12; the pairs are printed.

The denominator is the union of all three tools, not ground truth: the tools share upstream data, so an advisory none of them knows about is not counted.

Rerun with `sh bench/composer-2026-11/run.sh`. Results from 2026-11-12 are in `results/`.
