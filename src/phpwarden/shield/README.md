# shield: design and integration notes

`phpwarden shield` is shipped: one PHP file (the agent) loaded before a site's
own code, with a per-site policy that blocks exploit attempts against the
exploited vulnerabilities that site actually has, scoped to their entry points.
Every rule starts log-only and blocks only after it is promoted.

## CLI

```
phpwarden shield policy [PATH] [--out FILE] [--php-version X.Y.Z] [--php-sapi fpm|cgi|cli]
                        [--log FILE] [--no-limits] [--limit-path REGEX ...]
                        [--trust-proxy CIDR ...] [--json]
    # inventory from composer.lock / WordPress at PATH + feed -> policy JSON and a .php twin
phpwarden shield install [--dest DIR]
    # how to load the agent (auto_prepend_file, wp-config.php, public/index.php);
    # --dest copies phpwarden-shield.php there. Never edits server files.
phpwarden shield report LOG [--json]
    # hits per rule, top paths and clients, noisy rules
phpwarden shield promote POLICY --log LOG --i-understand-this-blocks-requests [--rule ID ...]
    # log -> block after a clean 7-day burn-in; refuses noisy rules; needs the explicit flag
```

## Dashboard

The project's **Shield** page (`saas/shieldui.py`) builds the policy from what
the project already reported (composer.lock findings, the WordPress plugin's
inventory, PHP version) and serves it with the agent as downloads. The agent's
summary (`phpwarden shield report --json`) is posted to `POST /v1/shield/hits`
with the project token and shown there. A Pro/Team owner can promote individual
rules to blocking only after 7 days since the first policy download, only for
rules the hits summary does not mark noisy, and only with an explicit
confirmation; one button returns every rule to log-only.

## Components

| File | Role |
|---|---|
| `integrations/php-shield/phpwarden-shield.php` | The agent. One PHP file, PHP 7.4+, no extensions. Loaded with `auto_prepend_file`. Logs by default, blocks only promoted rules in an `enforce` policy, fails open on any error, kill switch file/env. |
| `src/phpwarden/shield/library.py` | The rule library. Each rule has refs, an exploit-shape example and a near-miss. |
| `src/phpwarden/shield/policy.py` | `build_policy`, `build_policy_for_path`, `promote`, `write_policy` (JSON + `.php` twin for opcache). |
| `src/phpwarden/shield/matcher.py` | Python mirror of the agent's matching (tests, benchmark, replay). |
| `src/phpwarden/shield/report.py` | `summarize(log_lines)`, `to_text(summary)`. |
| `tests/test_shield_runtime.py` | Checks including the real agent under `php -S`. |
| `bench/shield-2026-11/` | Benchmark: 0 of 14,291 benign requests matched, 39/39 exploit shapes blocked, about 0.1 ms per request. |

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
- **Not an edge WAF**: no volumetric DDoS, TLS, CAPTCHA or JavaScript
  challenges; say so wherever it is sold. It does have per-client rate limits
  on sensitive endpoints (below), which slow brute force but cannot absorb a
  flood: every request still reaches PHP. See [EDGE.md](EDGE.md) for pairing it
  with Cloudflare or nginx.
- `trust_proxy` is an empty list by default: the client IP is `REMOTE_ADDR`.
  Behind a proxy, list the proxy's CIDRs; forwarded headers from any other peer
  are ignored. A bare `true` (older policies) trusts nothing.

## Rate limits

`build_policy(..., limits=True)` (the default; CLI `--no-limits` to skip) adds:

| limit | applies to | default |
|---|---|---|
| `wp-login` | POST /wp-login.php | 10 per client per 5 min |
| `wp-password-reset` | POST /wp-login.php?action=lostpassword/rp/resetpass | 5 per 15 min |
| `wp-jwt-auth` | POST /wp-json/jwt-auth/ | 10 per 5 min |
| `xmlrpc` | POST /xmlrpc.php | 30 per min |
| `xmlrpc-multicall` | POST /xmlrpc.php with system.multicall | 3 per min |
| `laravel-login` | POST /login (laravel/framework installed) | 10 per 5 min |
| `laravel-password-reset` | POST /forgot-password, /password/email, /password/reset | 5 per 15 min |
| `component-writes` | POST/PUT/PATCH/DELETE to admin-ajax.php and the REST routes of plugins/themes with rules | 60 per min |
| `rule-path-burst` | any path a rule is scoped to, counted per client and path | 20 per min |
| `custom-N` | operator paths (`limit_paths=`) | 10 per 5 min |

Each starts in mode `log`; hits are logged as rule `limit:<name>` with a count
(never the body). `promote` treats them exactly like rules (7-day burn-in,
operator acknowledgement, not noisy). A limit is noisy when it tripped for 10 or
more different clients: the threshold is probably too low for the site, or many
users share an address. Promoted and exceeded in an enforcing policy: `429`,
`Retry-After`, a one-line body.

Counters: APCu when enabled (per server; not shared across PHP-FPM hosts), else
a file store, `limits_store.dir` (default `phpwarden-shield.limits/` next to the
agent): one small file per client and limit, `flock`ed, files idle for an hour
pruned, capped at `max_files` (20,000). If neither works, limits switch off for
the request (fail open) and `limit:_store_unavailable` is logged once (marker
file `<log>.nostore`; delete it to re-arm). The window is two fixed buckets
weighted into a sliding estimate; windows longer than 30 minutes are not
supported by the file store pruning.
