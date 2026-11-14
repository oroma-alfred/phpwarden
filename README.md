# phpwarden

**PHP vulnerability scanner that ranks findings by real-world exploitation,
not CVSS.** Of about 19,500 PHP vulnerabilities in the feed, 54 are known to be
exploited (CISA KEV, as of 2026-11-14). phpwarden puts those first, then sorts
by EPSS probability, then CVSS — so a `composer.lock` with 30 findings tells
you which one to fix today.

It scans the PHP engine/FPM version, Composer dependencies and WordPress
installs against one bundled, offline advisory feed. Zero runtime dependencies
(Python 3.8+), Apache-2.0.

**Reproducible benchmark:** on four real PHP stacks, phpwarden found 295 of 295
known vulnerabilities, `composer audit` 286 and OSV.dev 262. Of 297 findings,
100 were rated critical or high and 4 were actually exploited or likely to be;
phpwarden ranked each of those first or second in its project. Method, numbers
and a script to rerun it:
[the benchmark write-up](https://phpwarden.io/blog/phpwarden-vs-composer-audit-osv-2026-11).

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
| WordPress file integrity (wordpress.org checksums, injected files) | `integrity` | Wordfence CLI malware-scan (partly) |
| Your own PHP code (75 rules) | `code` | — (not a PHPStan/Psalm replacement) |
| Live site from outside: exposed files, debug endpoints | `probe` | — |
| One ranked verdict across all of the above | `assess` | — |
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
  machine unless you opt in to `--report-to` or `feed update`. Two commands
  need the network by nature: `integrity` fetches checksums from wordpress.org,
  and `probe` talks only to the site you point it at.

## Install

```bash
composer require --dev phpwarden/phpwarden   # PHP projects → vendor/bin/phpwarden
pipx install phpwarden                       # Python-tooling box
brew install oroma-alfred/tap/phpwarden      # macOS / Linux with Homebrew
curl -LO https://phpwarden.io/phpwarden.pyz && python3 phpwarden.pyz scan   # single file, no install
docker run --rm phpwarden/phpwarden scan --version 8.3.10 --sapi fpm --os linux   # Docker Hub, amd64 + arm64
```

On modern macOS / Debian / Ubuntu a plain `pip install phpwarden` into the
system Python is blocked by [PEP 668](https://peps.python.org/pep-0668/); use
`pipx`, or a virtualenv:

```bash
python3 -m venv ~/.venvs/phpwarden && ~/.venvs/phpwarden/bin/pip install phpwarden
```

Docker usage (mounted projects, exit codes, CI, dashboard reporting) is on the
image's [Docker Hub page](https://hub.docker.com/r/phpwarden/phpwarden).

## Use

```bash
phpwarden scan                       # assess this host (auto-detects version/SAPI/OS)
phpwarden scan --version 8.3.10 --sapi fpm --os linux
phpwarden deps composer.lock         # Composer dependencies, KEV → reachability → EPSS → CVSS
phpwarden wordpress /var/www/html    # WordPress core, plugins, themes
phpwarden integrity /var/www/html    # tampered or injected files (vs wordpress.org checksums)
phpwarden detect /var/log/nginx/access.log   # exploit signatures in a log
phpwarden rules --format nginx --out php-block.conf   # PHP-specific WAF rules (or modsecurity)
phpwarden rules --format nginx --dry-run     # the same rules, log-only: nothing is blocked
phpwarden rules --replay /var/log/nginx/access.log    # what the rules would have blocked in an existing log
phpwarden probe https://example.com  # live check of a site you own: exposed files, debug endpoints, versions vs the feed
phpwarden code .                     # your own PHP: 75 high-signal rules, 74 on by default (injection, unserialize, WordPress handlers)
phpwarden assess . --url https://example.com --log access.log   # one ranked verdict; --out / --baseline shows what is fixed and verified
phpwarden report web01.json web02.json --out fleet.html   # aggregate a fleet view
phpwarden feed status                # which feed is active, how many advisories
phpwarden feed update                # pull a newer feed: free weekly snapshot, or the maintained channel with a key
```

`scan`, `deps`, `wordpress`, `probe` and `code` also take `--format sarif`
(SARIF 2.1.0, for GitHub code scanning and other CI dashboards).

`probe`, `code`, `assess`, `--format sarif`, `rules --dry-run` / `--replay` and
the no-key `feed update` are new in 2.2.0.

Every command takes `--json`. Exit codes are shared across subcommands and
built for gating: `0` clean, `1` exposed / vulnerable / signature hits / tampered
files / high or critical `code` and `probe` findings (`probe` also on any
known-exploited finding) / anything to act on now or this week (`assess`),
`2` possibly exposed (`scan`), `3` PHP version unknown (`scan`), `4` input
error, `5` `--report-to` upload failed on an otherwise clean run, `64` usage
error. Full table: `phpwarden --help`.


## New in 2.2.0

- **`phpwarden probe URL`**: a live check of a running site using GET and HEAD
  requests only. It looks for exposed files (`.env`, `.git`, backups), open debug
  endpoints, and the WordPress, plugin and PHP versions the site reveals, and
  matches those against the feed. Active checks run only after you prove the
  site is yours (DNS TXT record, a file, or a meta tag; `--print-token` shows
  how). Without that it reads the homepage and stops.
- **`phpwarden code PATH`**: 75 rules (74 on by default) for your own PHP code, following request
  data to `eval`, shell commands, SQL, `unserialize`, includes and redirects.
  It follows data across files (helper functions and classes elsewhere in the
  project, fixed includes, class properties); it is not a type checker like
  PHPStan or Psalm. `phpwarden code --list-rules` lists every rule.
- **`phpwarden assess`**: one ranked list from every view of a site: installed
  versions, your code, the live site from outside, and the access log, with the
  reason for each item ("exploited, reachable, visible from outside, already
  fetched"). `--out` then `--baseline` reports what is fixed and verified.
- **`--format sarif`** on `scan`, `deps`, `wordpress`, `probe` and `code`.
- **`rules --dry-run` and `rules --replay ACCESS_LOG`**: see what the WAF rules
  would block before they block anything.
- **Free weekly feed updates**: `phpwarden feed update` without a key pulls a
  weekly snapshot of the maintained feed. A vulnerability newly listed as known
  exploited is released to the free channel straight away.
- **Coverage commitment**: in-scope CISA KEV entries are in the maintained feed
  within 24 hours of listing, checked on every rebuild and published at
  https://phpwarden.io/feeds/kev-status.json. Details: https://phpwarden.io/sla
- **Editors**: a VS Code extension in `integrations/vscode` (build and install
  the `.vsix` from that folder; not on the Marketplace yet) and PhpStorm External Tool steps in
  `integrations/phpstorm`.

## Replacing Wordfence CLI

Wordfence closed new licences for its CLI in October 2026; Free licences stopped working on 2026-10-14 and Premium
licences are not renewed. phpwarden runs the same way (on the server, no plugin in the site) and covers:

| Wordfence CLI | phpwarden | Notes |
|---|---|---|
| `wordfence vuln-scan /path` | `phpwarden wordpress /path` | Same job, ranked by real-world exploitation; JSON/SARIF and CI exit codes. Also scans Composer and the PHP engine. |
| `wordfence malware-scan /path` | `phpwarden integrity /path` | Compares core and wordpress.org plugin files with official checksums; flags injected files, PHP in uploads and common backdoor code. **Not a signature scanner**: premium plugins and themes cannot be verified and are listed as such. |
| `wordfence remediate` | – | Reinstall the flagged component with WP-CLI. |
| `wordfence db-scan` | – | Not covered. |

Full guide: https://phpwarden.io/compare/phpwarden-vs-wordfence-cli#replace

## Send results to the dashboard

Any `scan`, `deps`, `wordpress` or `detect` run can post its result to
[app.phpwarden.io](https://app.phpwarden.io) for history across hosts.
It marks findings that become known-exploited; email and webhook alerts are on
Pro and Team, Slack on Team:

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
    rev: v2.1.0        # pin to a tag with `pre-commit autoupdate`
    hooks:
      - id: phpwarden-deps
        # args: ["--no-reachability"]   # faster: skip the reachability pass
```

**Hosts and cron** — WP-CLI, Laravel Forge / Ploi, plain cron and systemd
timer recipes are in [`docs/recipes.md`](docs/recipes.md).

## The feed

The bundled community feed (2026.11.13.3 in this release) works forever, offline:

- **~21,300 advisories**: ~8,800 Composer (from [OSV.dev](https://osv.dev) and
  [FriendsOfPHP](https://github.com/FriendsOfPHP/security-advisories)),
  ~12,300 WordPress (from [NVD](https://nvd.nist.gov): plugin, core and theme),
  and 145 PHP engine/FPM CVEs, including hand-curated entries with per-branch
  fixed versions, exposure conditions and detection signatures. About 19,700 carry an
  EPSS score; 41 distinct vulnerabilities were in KEV when this feed was built.
- **License-independent by construction.** Every source is open or
  public-domain (OSV, NVD, FriendsOfPHP, php-src release notes, CISA KEV, FIRST EPSS). No commercial
  vendor's feed is used, so coverage cannot be revoked or priced away.
- Every build passes `feedbuilder/check_feed.py` (no open-ended range with a
  known fix, no fixed version inside its own affected range, no duplicate
  (package|slug, cve)). The feed is assembled by `feedbuilder/` from a curated
  base plus bulk imports and enrichment; curated entries always win.

Updating the feed is optional and has two channels:

- **Free weekly.** `phpwarden feed update` with no key downloads a weekly
  snapshot of the maintained feed. A vulnerability newly listed as known
  exploited is released to this channel straight away. If the server cannot be
  reached, phpwarden keeps the feed it has and says so. Set
  `PHPWARDEN_FREE_FEED_URL=off` to stop the no-key update from calling out.
- **Maintained.** A [phpwarden.io](https://phpwarden.io) subscription gives a
  license key; `PHPWARDEN_LICENSE=... phpwarden feed update` then pulls the
  channel that is rebuilt twice a day.

Examples of hand-curated engine CVEs:

| CVE | What | Scope | Log signature |
|-----|------|-------|---------------|
| CVE-2019-11043 | PHP-FPM env_path_info RCE | FPM + nginx, config-gated | yes |
| CVE-2023-3824 | PHAR stack overflow RCE | any SAPI, untrusted PHAR | no |
| CVE-2024-4577 | PHP-CGI argument injection | Windows + CGI | yes |
| CVE-2024-8926 | cgi.force_redirect bypass | Windows + CGI | no |
| CVE-2024-8927 | cgi.force_redirect bypass | CGI / FPM | no |
| CVE-2024-11236 | DB-quoter integer overflow | any SAPI | no |
| CVE-2026-109618 / 109619 | php2shell FPM memory RCE | any SAPI | yes |

## Continuous guard

`scan` and `detect` are point-in-time. For always-on containment of
in-progress php2shell-class attacks (OOM on a worker, then that worker reused),
run `phpwarden-guard`, which boots in dry-run and never acts until you promote
it after a burn-in. See [`VALIDATION.md`](VALIDATION.md) for what was validated.

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
