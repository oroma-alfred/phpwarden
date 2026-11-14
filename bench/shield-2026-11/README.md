# phpwarden shield benchmark, November 2026

Stage 1 of phpwarden's inside-PHP protection: a single PHP file loaded before the
application (`auto_prepend_file`) that checks each request against rules for the
exploited vulnerabilities installed on that site, logging by default and blocking
only rules promoted after a burn-in. This measures three things: how much
ordinary traffic the rules match, whether they catch the exploit request shapes
they are written for, and what the agent costs per request.

Run by the maintainer on 2026-11-14 with PHP 8.5 on macOS (Apple silicon).
Rerun with `sh bench/shield-2026-11/run.sh`; this run's output is in
`results-2026-11-14.txt`. Nothing is sent to any host other than 127.0.0.1.

## Short version

| | Result |
|---|---|
| Benign requests matched (every one of the 33 library rules enabled) | **0 of 14,291** |
| Same, through the real PHP agent (1,500 sampled GETs + 2,000 POSTs) | **0 of 3,500** |
| Exploit-shape requests logged by the right rule (real agent) | **39 of 39** |
| Agent cost per request, 50-rule policy (CLI micro-benchmark) | **about 60 µs** (0.06 ms) |
| Added latency over HTTP, 50-rule policy (`php -S`, 2,000 requests) | **+0.07 ms p50, +0.10 ms p95** |

The performance budget was under 0.5 ms per request; the measured cost is about
a tenth of that.

## 1. False positives

Every library rule was switched on at once, which is the worst case: a real site
only gets the rules for vulnerabilities it has. The benign set is:

- the 12,291 generated GET requests of the WAF benchmark (`bench/waf-2026-11`):
  WordPress files, assets and REST routes, Laravel and Symfony routes, ASCII and
  non-ASCII searches and slugs (including the `%C3%AD` that trips naive soft-hyphen
  rules), UTM and pagination parameters, tokens, multi-line form text, and
  searches and slugs that *mention* `auto_prepend_file` and `allow_url_include`;
- 2,000 generated POST requests: contact forms (with multi-line, non-ASCII and
  "php.ini questions" text), comments, WooCommerce checkout, block-editor REST
  JSON (with `{{template}}` text and WordPress cookies), logins, GraphQL with a
  Laravel session cookie, and Laravel forms with nested array keys.

Result: no rule matched any of them, in the Python matcher (all 14,291) or in the
real agent (a 3,500-request sample).

## 2. True positives

Each rule carries the request shape its vulnerability needs, built from the
public advisory (sources in `src/phpwarden/shield/library.py`), and a near-miss
that must not match. Through the real agent, all 39 exploit-shape requests were
logged by the intended rule, none was blocked (log mode), and no near-miss was
logged by its rule.

| Area | Rules |
|---|---|
| PHP engine | CVE-2024-4577, CVE-2012-1823, CVE-2019-11043 |
| Composer | PHPUnit CVE-2017-9841, Laravel Ignition CVE-2021-3129, PHPMailer CVE-2016-10033, ThinkPHP CVE-2018-20062 and CVE-2019-9082, Magento CVE-2024-34102 and CVE-2022-24086, Drupal CVE-2018-7600 (8 and 7), Craft CMS CVE-2025-32432 and CVE-2024-56145, Roundcube CVE-2025-49113, phpMyAdmin CVE-2009-1151 |
| WordPress | File Manager CVE-2020-25213, LiteSpeed Cache CVE-2024-28000, Backup Migration CVE-2023-6553, WP Automatic CVE-2024-27956, Duplicator CVE-2020-11738, Social Warfare CVE-2019-9978, Kaswara CVE-2021-24284, Bricks CVE-2024-25600 (2 routes), WooCommerce Payments CVE-2023-28121, Essential Addons CVE-2023-32243, Really Simple Security CVE-2024-10924, core CVE-2026-119977 |
| Generic | PHP stream wrapper in a value, php.ini directive assigned in the query, serialized PHP object (only with a gadget-chain package installed), traversal toward wp-config.php / .env / /etc/passwd |

These are the shapes from the advisories. They show the rules do what they are
written to do; they do not show that every possible variant of an exploit is
caught (see below).

## 3. Cost per request

- **CLI micro-benchmark:** the agent's own work, run 20,000 times in one process
  with a 50-rule policy: about 60 µs per request for a typical GET or a contact
  form POST, including reading the policy. Loading the policy as a `.php` file
  (so opcache can keep it in memory) varied between 50 and 80 µs across runs in
  CLI mode; under PHP-FPM with opcache it avoids re-parsing JSON on every request.
- **HTTP:** `php -S` serving a trivial app, one client, 2,000 requests after a
  warm-up: p50 0.098 → 0.171 ms, p95 0.130 → 0.226 ms. A real application takes
  tens of milliseconds per request, so the shield's share is small.

## What this does not show, and what the shield does not do

- **It is not an edge WAF.** No DDoS or bot protection, no TLS, no rate limiting.
  Keep Cloudflare or your host's edge protection; the shield sits behind it.
- **It only protects vulnerabilities in the policy.** A site gets rules for the
  exploited vulnerabilities phpwarden finds installed on it, plus four generic
  checks. Anything else is not covered.
- **It sees the request, not the code path.** Stage 1 is plain PHP that runs
  before the application. It cannot see which function a value reaches; a later
  PHP-extension stage could hook the dangerous calls themselves.
- **Variants.** Each rule is written for the documented exploit shape. An
  attacker who finds a different route to the same bug may not match.
- **The corpora are generated.** No real site traffic was used; a real site's
  log-mode burn-in is the test that matters, which is why blocking needs it.
- **Measured on one machine.** Absolute timings differ elsewhere; the ratio to
  an application's own time is the useful number.
