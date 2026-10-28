# phpwarden

**A unified PHP security platform.** One tool, one feed, covering the full PHP
attack surface: engine and FPM CVE exposure, Composer dependency CVEs,
exploitation detection in logs, WAF blocking rules, and continuous worker-level
containment. Zero runtime dependencies (Python 3.8+).

phpwarden is the general successor to the single-CVE php2shell checker. Instead
of one vulnerability, it tracks many PHP CVEs over time through a **feed** — and
the feed is the part a subscription keeps current. The engine and the base
(community) feed are free and open; the maintained channel is the paid product.

## Surfaces it covers

| Surface | Command | Competes with |
|---------|---------|---------------|
| PHP engine / FPM CVE exposure | `scan` | image & network scanners |
| Composer dependency CVEs | `deps` | Snyk, `composer audit` |
| WordPress core, plugin and theme CVEs | `wordpress` | Patchstack, Wordfence |
| Exploitation signatures in logs | `detect` | SIEM content |
| WAF blocking rules (PHP-specific) | `rules` | the gap a generic WAF leaves |
| Fleet exposure dashboard | `report` | the CNAPP's PHP view |
| Continuous worker containment | guard daemon | nothing — unique |

## Why it is different

- **Version-accurate, per branch.** PHP backports fixes per branch, so a flat
  "you're on 8.3, upgrade" is wrong. phpwarden knows the fixed release for each
  branch of each CVE and compares precisely.
- **It never overclaims.** A CVE that needs a specific SAPI (FPM/CGI), OS, or
  configuration is reported as *possibly* exposed with the exact condition to
  confirm — not flagged as a certain hit, and not silently dismissed.
- **It covers exposure and exploitation.** `scan` tells you what you're exposed
  to; `detect` scans logs for the signatures of attempts; the guard daemon
  watches PHP-FPM for in-progress memory-corruption attacks.
- **Honesty over noise.** Validated at zero false positives on 2000 benign
  requests in the test suite.

## Install

```bash
pipx install phpwarden                 # recommended — installs the `phpwarden` command on PATH
composer require --dev phpwarden/phpwarden   # PHP projects: vendor/bin/phpwarden (wraps the same CLI)
./phpwarden.pyz scan                    # or no install at all, single file
docker run --rm phpwarden:2.0.0 scan --version 8.3.10 --sapi fpm --os linux
```

`pipx` is the right tool because phpwarden is a command-line app: it installs
into its own isolated environment and puts `phpwarden` (and `phpwarden-guard`)
on your PATH. On modern macOS / Debian / Ubuntu, a plain `pip install phpwarden`
into the system Python is blocked by [PEP 668](https://peps.python.org/pep-0668/)
(`externally-managed-environment`) — use `pipx`, or a virtualenv:

```bash
brew install pipx && pipx install phpwarden          # macOS (or: apt install pipx)
# — or a venv —
python3 -m venv ~/.venvs/phpwarden && ~/.venvs/phpwarden/bin/pip install phpwarden
```

Selling it as a subscription: the licensed feed server, key issuance/validation
and a Stripe webhook are in `server/` (see `server/README.md`).

## Use

```bash
phpwarden scan                       # assess this host (auto-detects version/SAPI/OS)
phpwarden scan --version 8.3.10 --sapi fpm --os linux
phpwarden scan --json                # machine-readable, for CI / dashboards
phpwarden feed status                # which feed is active, and is it licensed
phpwarden feed update                # pull the latest feed (needs a license key)
phpwarden detect /var/log/nginx/access.log   # scan a log for exploit signatures
phpwarden deps composer.lock         # scan Composer dependencies for known CVEs
phpwarden wordpress /var/www/html    # scan a WordPress install: core version, plugins, themes
phpwarden rules --format modsecurity # emit PHP-specific WAF blocking rules
phpwarden rules --format nginx --out php-block.conf
phpwarden report web01.json web02.json --out fleet.html   # aggregate a fleet view
```

Across a fleet, run `scan`, `deps` and `wordpress` with `--json` on each host,
collect the files, and `report` renders a single HTML dashboard: severity
tiles, exploited-in-wild count, and every finding by host and source.

`scan` exit codes: `0` clear, `1` exposed, `2` possibly exposed, `3` version
unknown — ready for a CI gate:

```bash
phpwarden scan || echo "PHP exposure found — see above"
```

## In CI (GitHub Actions)

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: primeagent001-bot/phpwarden-action@v1
    with:
      fail-on: exploited      # or critical | high | medium | exposed | never
```

The [phpwarden action](https://github.com/primeagent001-bot/phpwarden-action)
scans `composer.lock`, WordPress and a production PHP version on every push,
writes a job-summary table and `composer.lock` line annotations, can upload
SARIF to the Security tab, and can report to your dashboard.

Not on GitHub? Ready-made templates for
[GitLab CI](integrations/gitlab-ci/phpwarden.gitlab-ci.yml) and
[Bitbucket Pipelines](integrations/bitbucket/bitbucket-pipelines.yml) install the
CLI, keep `phpwarden.json` as an artifact and fail the job only on exit 1
(vulnerable) or 2 (possibly exposed). Laravel apps (10, 11, 12 and 13) can
`composer require --dev phpwarden/laravel` and run `php artisan phpwarden:scan`
instead; see the [phpwarden/laravel](https://packagist.org/packages/phpwarden/laravel)
package.

### Pre-commit hook

Block a vulnerable `composer.lock` before it is committed:

```yaml
repos:
  - repo: https://github.com/primeagent001-bot/phpwarden
    rev: main        # pin to a tag with `pre-commit autoupdate`
    hooks:
      - id: phpwarden-deps
        # args: ["--no-reachability"]   # faster: skip the reachability pass
```

## The subscription

The base feed ships inside the package and works forever, offline. A license key
unlocks the maintained channel, which adds new PHP CVEs — version ranges,
exposure conditions, and detection signatures — as they are triaged:

```bash
export PHPWARDEN_LICENSE=...          # from your subscription
phpwarden feed update
```

Without a key, `phpwarden` runs the free community feed and says so. Nothing
phones home unless you run `feed update`.

## Current coverage (feed 2026.10.26.2)

- **20,900+ advisories bundled**, offline: ~8,600 Composer (from
  [OSV.dev](https://osv.dev) + [FriendsOfPHP](https://github.com/FriendsOfPHP/security-advisories);
  84% carry a CVSS-derived severity),
  ~12,300 WordPress advisories (from [NVD](https://nvd.nist.gov): ~11,800 plugin
  across 5,900 slugs, 345 WordPress core, 165 theme — theme classification is
  description-based because NVD's CPE has no plugin/theme flag),
  and the curated PHP engine/FPM CVEs. 19,400+ carry an EPSS exploitation score.
  Every build passes `feedbuilder/check_feed.py` (no open-ended range with a
  known fix, no "fixed" version inside its own affected range, no duplicate
  (package|slug, cve), every slug backed by its CPE product or a wordpress.org
  reference).
- **License-independent by construction.** Every source is open or
  public-domain (OSV, NVD, FriendsOfPHP, CISA KEV, FIRST EPSS). No commercial
  vendor's licensed feed is used, so coverage can never be revoked or priced
  away. `composer audit`-grade dependency coverage and Patchstack-scale
  WordPress coverage, with no vendor key.
- **8 hand-curated PHP engine/FPM CVEs** (2019–2026), each with per-branch fixed
  versions, exposure conditions and detection signatures (table below), ranges
  verified against vendor advisories.
- **Curated WordPress plugin advisories**, extensible to Patchstack scale
  through the maintained subscription channel.
- **Real-world exploitation enrichment.** Every advisory with a CVE is joined to
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (is it actively exploited, and used in ransomware) and
  [FIRST EPSS](https://www.first.org/epss/) (probability of exploitation).
  Findings are ranked **exploitation-first**, not by CVSS alone — the
  prioritisation commercial scanners charge for, here free and offline.

The feed is assembled by `feedbuilder/` from a curated base plus bulk imports
and enrichment (`feedbuilder/README.md`); curated entries always win over
imported ones.

| CVE | What | Scope |
|-----|------|-------|
| CVE-2019-11043 | PHP-FPM env_path_info RCE | FPM + nginx, config-gated |
| CVE-2023-3824 | PHAR stack overflow RCE | any SAPI, untrusted PHAR |
| CVE-2024-4577 | PHP-CGI argument injection | Windows + CGI |
| CVE-2024-8926 / 8927 | cgi.force_redirect bypass | CGI / FPM |
| CVE-2024-11236 | DB-quoter integer overflow | any SAPI |
| CVE-2026-109618 / 109619 | php2shell FPM memory RCE | any SAPI |

## Continuous guard

`phpwarden scan` and `detect` are point-in-time. For always-on containment of
in-progress php2shell-class attacks (OOM on a worker, then that worker reused),
run the guard daemon, which boots in dry-run and never acts until you promote it
after a burn-in. See the guard's own DESIGN document.

## Honest limits

- The deterministic version census is the reliable backbone; behavioral
  detection is best-effort and a clean exploit can leave little trace.
- `scan` only knows what it can observe. Anything it cannot determine (SAPI, OS,
  app-level conditions) is reported as *possibly* exposed, not safe.
- Field validation against production traffic requires a live PHP host; the
  test suite validates against synthetic traffic.

## License

Open-core. The **engine** (`src/phpwarden/`) and the **bundled community feed**
are **Apache-2.0** — free to use, inspect, modify and redistribute (see
[`LICENSE`](LICENSE)). The **hosted service** (`saas/`, `server/`) and the
**maintained feed** are proprietary/commercial. Full scope in
[`LICENSING.md`](LICENSING.md).
