# phpwarden recipes

Copy-paste snippets for running phpwarden on a schedule outside CI: shared
WordPress hosts, Laravel Forge / Ploi servers, plain cron and systemd. Every
recipe ends by posting the result to the dashboard, which is the one-liner
that turns a local scan into fleet history:

```bash
phpwarden scan --report-to https://app.phpwarden.io/v1/reports --report-token <token>
```

What you get back is ranked by real-world exploitation — CISA KEV first, then
EPSS, then CVSS. Of about 19,500 PHP vulnerabilities in the feed, 54 are known to be
exploited (as of 2026-11-14); those are the lines at the top.

Assumptions throughout:

- `phpwarden` is on `PATH` (`pipx install phpwarden`, `vendor/bin/phpwarden`
  from `composer require --dev phpwarden/phpwarden`, or the single file from https://phpwarden.io/phpwarden.pyz, run as `python3 phpwarden.pyz`).
- The project token lives in the environment, not in the command line, so it
  does not show up in `ps` or shell history. The CLI reads
  `PHPWARDEN_REPORT_URL` and `PHPWARDEN_REPORT_TOKEN` when the flags are
  omitted.
- Exit codes: `0` clean, `1` vulnerable/exposed, `2` possibly exposed (`scan`),
  `3` PHP version unknown (`scan`), `4` input error, `5` upload failed on an
  otherwise clean run, `64` usage error. Local output is always printed before
  the upload, so a dead dashboard never hides a finding.

Subcommands used below and their flags, as implemented in the CLI:
`scan [--version X.Y.Z] [--sapi fpm|cgi|cli] [--os linux|windows|darwin] [--php BIN] [--json]`,
`deps LOCKFILE [--project DIR] [--no-reachability] [--json]`,
`wordpress PATH [--host LABEL] [--json]`, `detect LOGFILE [--json]`,
`report FILES... [--out HTML]`. `--report-to URL --report-token TOKEN` is
accepted by `scan`, `deps`, `wordpress` and `detect`. The last three recipes
also use `probe URL [--passive] [--max-requests N]`,
`rules [--format nginx|modsecurity] [--dry-run] [--replay ACCESS_LOG]`,
`code PATH` and `--format sarif` (all new in 2.2.0).

---

## WordPress hosts

### One site, via WP-CLI

WP-CLI finds the install for you; phpwarden scans core, plugins and themes
from the files, so the database is never touched and nothing needs to be
installed into WordPress:

```bash
export PHPWARDEN_REPORT_URL=https://app.phpwarden.io/v1/reports
export PHPWARDEN_REPORT_TOKEN=pw_live_xxxxxxxx

WP_ROOT=$(wp eval 'echo rtrim(ABSPATH, "/");' --path=/var/www/example.com/public)
phpwarden wordpress "$WP_ROOT" --host example.com
```

### Every site on the box, nightly (cron)

`/etc/cron.d/phpwarden-wordpress`, with one `wordpress` run per document root
and the host label set to the site name so the dashboard groups them:

```cron
# m h dom mon dow user  command
15 3 * * *  www-data  . /etc/phpwarden.env; for d in /var/www/*/public; do site=$(basename "$(dirname "$d")"); phpwarden wordpress "$d" --host "$site" --json > "/var/log/phpwarden/$site.json" 2>>/var/log/phpwarden/cron.log; done
```

`/etc/phpwarden.env` (mode `0600`, owned by the cron user):

```sh
PHPWARDEN_REPORT_URL=https://app.phpwarden.io/v1/reports
PHPWARDEN_REPORT_TOKEN=pw_live_xxxxxxxx
```

Keep the `--json` files if you also want a local fleet page:

```bash
phpwarden report /var/log/phpwarden/*.json --out /var/www/status/phpwarden.html
```

### The PHP engine too

Hosts upgrade PHP per pool, so scan the engine on each box alongside the
sites. Without flags, `scan` detects the local `php` binary, SAPI and OS:

```bash
phpwarden scan --json > /var/log/phpwarden/engine.json
# or, for a pool running a different binary:
phpwarden scan --php /usr/bin/php8.2 --sapi fpm
```

### Managed hosting without cron access

If you can only run WP-CLI, run phpwarden on your own machine against a copy
of `wp-content` (plugin and theme versions come from the file headers, so an
`rsync` of `wp-content/plugins` and `wp-content/themes` plus
`wp-includes/version.php` is enough):

```bash
rsync -a --include='wp-includes/version.php' --include='wp-content/plugins/***' \
  --include='wp-content/themes/***' --include='*/' --exclude='*' \
  host:/var/www/example.com/public/ ./example.com/
phpwarden wordpress ./example.com --host example.com --report-to https://app.phpwarden.io/v1/reports --report-token <token>
```

---

## Laravel Forge

Forge runs scheduled jobs as a server user on a frequency you pick, and
deploy scripts run as `forge` from the release directory.

### Deploy script (fail the deploy on a vulnerable lockfile)

Add after `composer install`, before `php artisan migrate`:

```bash
# phpwarden: block the deploy if composer.lock carries a known-vulnerable package.
# Exit 1 = vulnerable; anything else non-zero means the scan did not run.
phpwarden deps composer.lock --project . \
  --report-to https://app.phpwarden.io/v1/reports --report-token "$PHPWARDEN_REPORT_TOKEN"
```

Put `PHPWARDEN_REPORT_TOKEN` in the site's Environment tab (Forge exports the
`.env` to the deploy shell only if you source it; simplest is to add
`export PHPWARDEN_REPORT_TOKEN=pw_live_xxxxxxxx` at the top of the deploy
script, or set it in `/home/forge/.bashrc`). To warn instead of block, append
`|| true` — the dashboard still records the result.

If the app uses `phpwarden/laravel`, the same step is
`php artisan phpwarden:scan --fail-on=exploited`, which fails only on CISA KEV
findings.

### Scheduled job (daily engine + dependency scan)

Forge > Server > Scheduler > New Scheduled Job, user `forge`, frequency
Daily:

```bash
cd /home/forge/example.com/current && . /home/forge/.phpwarden.env && phpwarden scan && phpwarden deps composer.lock --project .
```

with `/home/forge/.phpwarden.env`:

```sh
export PHPWARDEN_REPORT_URL=https://app.phpwarden.io/v1/reports
export PHPWARDEN_REPORT_TOKEN=pw_live_xxxxxxxx
```

Forge marks the job failed on a non-zero exit, so a new finding shows up both
there and in the dashboard.

---

## Ploi

### Deploy script

Ploi deploy scripts run as the site user in the release directory:

```bash
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
phpwarden deps composer.lock --project . \
  --report-to https://app.phpwarden.io/v1/reports --report-token "$PHPWARDEN_REPORT_TOKEN"
```

Set `PHPWARDEN_REPORT_TOKEN` under the site's Environment settings, or export
it at the top of the script. Ploi stops the deploy on a non-zero exit; append
`|| true` for warn-only.

### Cronjob

Ploi > Server > Cronjobs, user `ploi`, frequency Daily:

```bash
. /home/ploi/.phpwarden.env && cd /home/ploi/example.com && phpwarden scan && phpwarden deps composer.lock --project .
```

Same `.phpwarden.env` as the Forge recipe.

---

## Plain cron

`/etc/cron.d/phpwarden`, scanning the engine daily and a Composer project
weekly, token from a root-only env file:

```cron
SHELL=/bin/sh
# m  h dom mon dow user  command
0    4  *   *   *  root  . /etc/phpwarden.env; phpwarden scan >> /var/log/phpwarden.log 2>&1
30   4  *   *   1  root  . /etc/phpwarden.env; phpwarden deps /srv/app/composer.lock --project /srv/app >> /var/log/phpwarden.log 2>&1
```

Add `--json` and redirect to a file instead if you want to aggregate hosts
locally with `phpwarden report`.

### Web logs for exploit signatures

```cron
*/30 * * * *  root  . /etc/phpwarden.env; phpwarden detect /var/log/nginx/access.log > /dev/null || logger -t phpwarden "exploit signatures in access.log (exit $?)"
```

`detect` exits `1` on hits and also posts them when `--report-to` (or the env
vars) are set.

---

## systemd timer

Two units; the service runs once, the timer fires it daily with a random
offset so a fleet does not scan at the same second.

`/etc/systemd/system/phpwarden.service`:

```ini
[Unit]
Description=phpwarden: PHP engine and Composer vulnerability scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# PHPWARDEN_REPORT_URL and PHPWARDEN_REPORT_TOKEN, mode 0600
EnvironmentFile=/etc/phpwarden.env
WorkingDirectory=/srv/app
ExecStart=/usr/local/bin/phpwarden scan
ExecStart=/usr/local/bin/phpwarden deps /srv/app/composer.lock --project /srv/app
# exit 1 (vulnerable) is a result, not a crash; let the dashboard carry it
SuccessExitStatus=1 2
```

`/etc/systemd/system/phpwarden.timer`:

```ini
[Unit]
Description=Daily phpwarden scan

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now phpwarden.timer
systemctl start phpwarden.service && journalctl -u phpwarden --no-pager -n 30
```

Drop `SuccessExitStatus` if you want `systemctl --failed` to light up on a
finding instead. For a WordPress box, add
`ExecStart=/usr/local/bin/phpwarden wordpress /var/www/html --host %H` (`%H`
is the hostname).

---

## Alongside Trivy (containers, OS packages, JavaScript)

phpwarden covers PHP: the engine, Composer packages and WordPress. It does not
scan container images, OS packages, npm dependencies or infrastructure files.
[Trivy](https://trivy.dev) does. Run both and upload both SARIF files (GitHub
Actions; the job needs `permissions: security-events: write`):

```yaml
steps:
  - uses: actions/checkout@v4
  - run: pip install "phpwarden>=2.2,<3"
  - run: phpwarden deps composer.lock --format sarif > phpwarden.sarif || true
  - run: phpwarden code . --format sarif > phpwarden-code.sarif || true
  # install Trivy first (see trivy.dev), then:
  - run: trivy fs --format sarif --output trivy.sarif .
  - uses: github/codeql-action/upload-sarif@v3
    with: { sarif_file: phpwarden.sarif, category: phpwarden-deps }
  - uses: github/codeql-action/upload-sarif@v3
    with: { sarif_file: phpwarden-code.sarif, category: phpwarden-code }
  - uses: github/codeql-action/upload-sarif@v3
    with: { sarif_file: trivy.sarif, category: trivy }
  - run: phpwarden deps composer.lock      # the exit code gates the build
```

For a built image use `trivy image --format sarif --output trivy-image.sarif your/image:tag`.
Trivy also reads `composer.lock`, so some PHP packages appear in both reports;
use phpwarden's order (known exploited, then EPSS) to decide what to fix first
in PHP.

## A client site you can only reach by URL

`probe` checks a running site from outside with GET and HEAD requests only. The
active checks need proof that the site is yours:

```bash
phpwarden probe https://client.example --print-token   # token + three ways to publish it
phpwarden probe https://client.example                 # run once the token is in place
phpwarden probe https://client.example --json > client.json
```

Weekly from cron, mailing only when something high, critical or known
exploited shows up (exit code 1):

```cron
15 6 * * 1  phpwarden probe https://client.example > /tmp/probe.txt 2>&1 || mail -s "phpwarden probe: client.example" you@example.com < /tmp/probe.txt
```

## Try the WAF rules before they block

```bash
phpwarden rules --replay /var/log/nginx/access.log     # what would have been refused, from a log you already have
phpwarden rules --format nginx --dry-run --out /etc/nginx/snippets/phpwarden-dryrun.conf
```

The replay report flags any matching request your server had answered 2xx/3xx:
check those for false positives before enabling the blocking rules.

## Reading the result

Every finding line carries the exploitation tag the ranking is based on:

```
  plugin wp-file-manager 6.0  CVE-2020-25213 critical (CVSS 10)  [KEV, EPSS 97% (p100)]
```

`KEV` means CISA lists it as exploited in the wild (`KEV·ransomware` when
used in ransomware campaigns); `EPSS` is the 30-day exploitation probability
and percentile. Fix those first, regardless of what the CVSS column says.

## Block exploits of what a site runs, inside PHP

Build the policy on the server (or in the deploy step) from what is installed,
load the agent before the app, and let it log for a week before promoting:

```bash
cd /var/www/shop
phpwarden shield policy . --php-version "$(php -r 'echo PHP_VERSION;')" --php-sapi fpm
phpwarden shield install --dest /var/www/shop          # prints the auto_prepend_file / require line
# a week later, after reading the log:
phpwarden shield report /var/www/shop/phpwarden-shield.log
phpwarden shield promote phpwarden-shield.policy.json --log /var/www/shop/phpwarden-shield.log \
  --i-understand-this-blocks-requests
```

Rebuild the policy after each deploy so upgraded components lose their rules.
To stop it at once: `touch /var/www/shop/phpwarden-shield.off`.
