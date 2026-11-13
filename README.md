# phpwarden

**PHP vulnerability scanner that ranks findings by real-world exploitation,
not CVSS.** Of the ~21,100 PHP advisories in the feed, 43 are actually being
exploited (CISA KEV, as of 2026-11-12). phpwarden puts those first, then sorts
by EPSS probability, then CVSS — so a `composer.lock` with 30 findings tells
you which one to fix today.

It scans the PHP engine/FPM version, Composer dependencies and WordPress
installs against one bundled, offline advisory feed. Zero runtime dependencies
(Python 3.8+), Apache-2.0.

```bash
$ phpwarden deps composer.lock
18 vulnerable package(s) in composer.lock; 0 actively exploited (KEV). Ranked by exploitation risk, then reachability:

  symfony/http-kernel 5.4.0  CVE-2022-24894 medium (CVSS 5.9)  [EPSS 4% (p90)]
      Symfony storing cookie headers in HttpCache
      fixed in: 4.4.50, 5.4.20, 6.0.20, 6.1.12, 6.2.6

  phpmailer/phpmailer 6.1.5  CVE-2020-13625 high (CVSS 7.5)  [EPSS 4% (p90)]
      ...
```

## Surfaces it covers

| Surface | Command | Instead of |
|---------|---------|------------|
| PHP engine / FPM CVE exposure | `scan` | image & network scanners |
| Composer dependency CVEs | `deps` | Snyk, `composer audit` |
| WordPress core, plugin and theme CVEs | `wordpress` | Patchstack, Wordfence |
| Exploitation signatures in logs | `detect` | SIEM content |
| WAF blocking rules (PHP-specific) | `rules` | the gap a generic WAF leaves |
| Fleet exposure dashboard | `report` | the CNAPP's PHP view |
| Continuous worker containment | `phpwarden-guard` daemon | — |

## Why it is different

- **Exploitation first.** Every advisory with a CVE is joined to
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (exploited in the wild, used in ransomware) and
  [FIRST EPSS](https://www.first.org/epss/) (probability of exploitation).
  Findings are ordered KEV, then reachability (`deps`), then EPSS, then CVSS —
  in the text output, the JSON and the dashboard alike.
- **Version-accurate, per branch.** PHP backports fixes per branch, so a flat
  "you're on 8.3, upgrade" is wrong. phpwarden knows the fixed release for each
  branch of each engine CVE and compares precisely.
- **It never overclaims.** A CVE that needs a specific SAPI (FPM/CGI), OS or
  configuration is reported as *possibly* exposed with the exact condition to
  confirm — not flagged as a certain hit, and not silently dismissed.
- **Offline by default.** The feed ships inside the package. Nothing leaves the
  machine unless you opt in to `--report-to` or `feed update`.

## Install

```bash
composer require --dev phpwarden/phpwarden   # PHP projects → vendor/bin/phpwarden
pipx install phpwarden                       # Python-tooling box
python3 phpwarden.pyz scan                   # single file, no install
docker build -t phpwarden . && docker run --rm phpwarden scan --version 8.3.10 --sapi fpm --os linux
```

On modern macOS / Debian / Ubuntu a plain `pip install phpwarden` into the
system Python is blocked by [PEP 668](https://peps.python.org/pep-0668/); use
`pipx`, or a virtualenv:

```bash
python3 -m venv ~/.venvs/phpwarden && ~/.venvs/phpwarden/bin/pip install phpwarden
```

Docker usage (mounted projects, CI, dashboard reporting) is in
[`docs/docker.md`](docs/docker.md).

## Use

```bash
phpwarden scan                       # assess this host (auto-detects version/SAPI/OS)
phpwarden scan --version 8.3.10 --sapi fpm --os linux
phpwarden deps composer.lock         # Composer dependencies, KEV → reachability → EPSS → CVSS
phpwarden wordpress /var/www/html    # WordPress core, plugins, themes
phpwarden integrity /var/www/html    # tampered or injected files (vs wordpress.org checksums)
phpwarden detect /var/log/nginx/access.log   # exploit signatures in a log
phpwarden rules --format nginx --out php-block.conf   # PHP-specific WAF rules (or modsecurity)
phpwarden report web01.json web02.json --out fleet.html   # aggregate a fleet view
phpwarden feed status                # which feed is active, how many advisories
```

Every command takes `--json`. Exit codes are shared across subcommands and
built for gating: `0` clean, `1` exposed / vulnerable / signature hits,
`2` possibly exposed (`scan`), `3` PHP version unknown (`scan`), `4` input
error, `5` `--report-to` upload failed on an otherwise clean run, `64` usage
error. Full table: `phpwarden --help`.

## Send results to the dashboard

Any `scan`, `deps`, `wordpress` or `detect` run can post its result to
[app.phpwarden.io](https://app.phpwarden.io) for history across hosts and
alerts when a finding you already carry lands in KEV:

```bash
phpwarden scan --report-to https://app.phpwarden.io/v1/reports --report-token <token>
```

The token comes from the project page in the dashboard; it can also be set as
`PHPWARDEN_REPORT_TOKEN` (and the URL as `PHPWARDEN_REPORT_URL`). Local output
is always printed first, so an unreachable dashboard never hides a finding.

## In CI

**GitHub Actions** — the [phpwarden action](https://github.com/oroma-alfred/phpwarden-action)
scans `composer.lock`, a WordPress path and your production PHP version, writes
a job-summary table and `composer.lock` line annotations, can upload SARIF to
the Security tab, and can report to the dashboard:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: oroma-alfred/phpwarden-action@v1
    with:
      fail-on: exploited      # fail only on CISA-KEV findings; or critical | high | medium | exposed | never
      report-url: https://app.phpwarden.io/v1/reports
      report-token: ${{ secrets.PHPWARDEN_TOKEN }}
```

`fail-on` is an input of the action. The bare CLI exits `1` on any vulnerable
package; see the templates below for how a job uses that.

**GitLab CI / Bitbucket Pipelines** — ready-made templates in
[`integrations/gitlab-ci/`](integrations/gitlab-ci/phpwarden.gitlab-ci.yml) and
[`integrations/bitbucket/`](integrations/bitbucket/bitbucket-pipelines.yml)
install the CLI, keep `phpwarden.json` as an artifact, fail the job on exit
`1` or `2`, and forward to the dashboard when a token variable is set.

**Laravel** — `composer require --dev phpwarden/laravel` adds
`php artisan phpwarden:scan` (same exit codes, plus `--fail-on=exploited`);
see [phpwarden/laravel](https://packagist.org/packages/phpwarden/laravel).

**pre-commit** — block a vulnerable `composer.lock` before it is committed:

```yaml
repos:
  - repo: https://github.com/oroma-alfred/phpwarden
    rev: main        # pin to a tag with `pre-commit autoupdate`
    hooks:
      - id: phpwarden-deps
        # args: ["--no-reachability"]   # faster: skip the reachability pass
```

**Hosts and cron** — WP-CLI, Laravel Forge / Ploi, plain cron and systemd
timer recipes are in [`docs/recipes.md`](docs/recipes.md).

## The feed

The bundled community feed (currently 2026.10.31.2) works forever, offline:

- **~21,100 advisories**: ~8,600 Composer (from [OSV.dev](https://osv.dev) and
  [FriendsOfPHP](https://github.com/FriendsOfPHP/security-advisories)),
  ~12,300 WordPress (from [NVD](https://nvd.nist.gov): plugin, core and theme),
  and 145 PHP engine/FPM CVEs, including hand-curated entries with per-branch
  fixed versions, exposure conditions and detection signatures. 19,400+ carry an
  EPSS score; 42 were in KEV when this feed was built.
- **License-independent by construction.** Every source is open or
  public-domain (OSV, NVD, FriendsOfPHP, CISA KEV, FIRST EPSS). No commercial
  vendor's feed is used, so coverage cannot be revoked or priced away.
- Every build passes `feedbuilder/check_feed.py` (no open-ended range with a
  known fix, no fixed version inside its own affected range, no duplicate
  (package|slug, cve)). The feed is assembled by `feedbuilder/` from a curated
  base plus bulk imports and enrichment; curated entries always win.

A [phpwarden.io](https://phpwarden.io) subscription unlocks the maintained
channel — new advisories and KEV/EPSS refreshes as they are triaged — via
`PHPWARDEN_LICENSE=... phpwarden feed update`. Without a key, phpwarden runs
the community feed and says so.

Curated engine CVEs with detection signatures:

| CVE | What | Scope |
|-----|------|-------|
| CVE-2019-11043 | PHP-FPM env_path_info RCE | FPM + nginx, config-gated |
| CVE-2023-3824 | PHAR stack overflow RCE | any SAPI, untrusted PHAR |
| CVE-2024-4577 | PHP-CGI argument injection | Windows + CGI |
| CVE-2024-8926 / 8927 | cgi.force_redirect bypass | CGI / FPM |
| CVE-2024-11236 | DB-quoter integer overflow | any SAPI |
| CVE-2026-109618 / 109619 | php2shell FPM memory RCE | any SAPI |

## Continuous guard

`scan` and `detect` are point-in-time. For always-on containment of
in-progress php2shell-class attacks (OOM on a worker, then that worker reused),
run `phpwarden-guard`, which boots in dry-run and never acts until you promote
it after a burn-in. See the guard's DESIGN document.

## Honest limits

- The deterministic version census is the reliable backbone; behavioural
  detection is best-effort and a clean exploit can leave little trace.
- `scan` only knows what it can observe. Anything it cannot determine (SAPI, OS,
  app-level conditions) is reported as *possibly* exposed, not safe.
- The KEV count above is a dated snapshot; `phpwarden feed status` and the
  bundled feed are the source of truth for the version you run.

## License

Open-core. The **engine** (`src/phpwarden/`) and the **bundled community feed**
are **Apache-2.0** (see [`LICENSE`](LICENSE)). The **hosted service** (`saas/`,
`server/`) and the **maintained feed** are proprietary. Full scope in
[`LICENSING.md`](LICENSING.md).
