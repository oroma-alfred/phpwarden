# phpwarden shield: integration note (stage 1)

Built and tested; **not wired into the CLI, dashboard or docs yet.** This note is
for the next step.

## What exists

| File | Role |
|---|---|
| `integrations/php-shield/phpwarden-shield.php` | The agent. One PHP file, PHP 7.4+, no extensions. Loaded with `auto_prepend_file`. Logs by default, blocks only promoted rules in an `enforce` policy, fails open on any error, kill switch file/env. |
| `src/phpwarden/shield/library.py` | 33 rules: 3 engine, 13 Composer, 13 WordPress, 4 generic. Each has refs, an exploit-shape example and a near-miss. |
| `src/phpwarden/shield/policy.py` | `build_policy(inventory, feed)`, `build_policy_for_path(path, feed)`, `promote(policy, stats, operator_ack=True)`, `write_policy(policy, path)` (JSON + `.php` twin for opcache). |
| `src/phpwarden/shield/matcher.py` | Python mirror of the agent's matching (tests, benchmark, replay). |
| `src/phpwarden/shield/report.py` | `summarize(log_lines)`, `to_text(summary)`: hits per rule, top paths/clients, noisy rules. |
| `tests/test_shield_runtime.py` | 28 checks incl. the real agent under `php -S`. |
| `bench/shield-2026-11/` | Benchmark: 0/14,291 benign matches, 39/39 exploit shapes, ~60 µs per request. |

## Proposed CLI (cli.py)

```
phpwarden shield policy [PATH] [--php-version X.Y.Z] [--php-sapi fpm|cgi|cli] [--out policy.json]
    # inventory from composer.lock / WordPress at PATH + feed -> policy.json and policy.php;
    # prints included rules and why, and the skipped ones with the reason
phpwarden shield install [--wordpress|--laravel|--php-ini]
    # prints instructions (do not edit server files automatically):
    #   php.ini / .user.ini:  auto_prepend_file=/path/phpwarden-shield.php
    #   WordPress:            mu-plugin that requires the agent (runs before plugins)
    #                         or `require` as the first line of wp-config.php (earlier, preferred)
    #   Laravel:              require at the top of public/index.php
    # and where to put phpwarden-shield.policy.php
phpwarden shield report LOG [--json]          # report.summarize / to_text
phpwarden shield promote POLICY --log LOG --i-understand-this-blocks-requests [--rule ID ...]
    # promote(): refuses before 7 days, refuses noisy rules, needs the explicit flag
phpwarden shield check POLICY --replay ACCESS_LOG
    # matcher over an existing access log (GET only) to preview hits before installing
```

The agent file should ship in the wheel (package data) and be copied by
`shield install`, or be downloadable from phpwarden.io like `phpwarden.pyz`.

## Proposed dashboard

- Project page "Shield" card: download the policy built from the latest reports
  (composer + WordPress inventory are already stored) and the agent file;
  install instructions per stack.
- Weekly refresh: rebuild the policy when the feed or the inventory changes; a
  newly exploited CVE on the site adds its rule in log mode; a verified fix drops it.
- Hits view: the agent posts its log summary (`phpwarden shield report --report-to`)
  or the WordPress plugin forwards it; show hits per rule, top clients.
- Promote button per rule, enabled after 7 days without noise, with an explicit
  confirmation. Demote / kill switch button that pushes a log-only policy.

## Plan gating suggestion

- Free: policy + agent in log mode (shows value: "these exploit attempts hit a
  vulnerability you have").
- Pro/Team: blocking (promotion), weekly automatic policy refresh, hits in the
  dashboard and alerts on hits for exploited CVEs.

## Risks

- **It runs in the production request path.** Fail-open, a 5 ms time budget,
  and the kill switch are in place, but a bad regex in a future rule could still
  slow requests: keep the library's tests and the benchmark in CI.
- **Blocking can break a legitimate feature** that happens to use a matching
  parameter. That is what the 7-day log-only burn-in and the noisy-rule check
  are for; never promote automatically.
- **Pure-PHP prepend runs after the web server.** Requests to static files and
  to PHP files outside the prepend scope are not seen (e.g. if a plugin file is
  served by a different pool or `auto_prepend_file` is overridden by `.user.ini`).
- **Not an edge WAF**: no DDoS, bots, TLS or rate limiting; say so wherever it
  is sold.
- `trust_proxy` is off by default; behind a proxy the logged client IP is the
  proxy unless the policy turns it on.
