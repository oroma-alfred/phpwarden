# Probe correctness benchmark, November 2026

`phpwarden probe` checked against seven small sites served on `127.0.0.1`,
where what is exposed is known exactly. Run by the maintainer on 2026-11-14
(phpwarden 2.1.1 plus the unreleased `probe` command). Rerun with
`sh bench/probe-2026-11/run.sh`; it needs only python3 and makes no request to
any other host. That run's output is in `results-2026-11-14.txt`.

**Short version: it finds everything that is planted and stays quiet on
honest sites. The first run found one real weakness, 8 false positives on a
site that answers 200 to every URL with a page that changes on each request;
that was fixed the same day and the rerun shows 0 false positives on all six
sites with nothing exposed.**

The fix (`same_as_catch_all` in `src/phpwarden/probe.py`): a hit is discarded
when the check's own marker is already present on the page served for a random
nonexistent path, or when the two pages are more than 90% similar. A run that
hits the request cap is now reported as incomplete instead of looking clean.
`results-2026-11-14.txt` is the first run, `results-2026-11-14-after-fix.txt`
the rerun; the table and notes below describe the first run.

## Method

Each site proves ownership with the `phpwarden-verify` meta tag, so the probe
runs its active checks: 19 exposed-file checks and 10 debug or admin endpoint
checks. Findings of those two kinds are compared with what the site really
serves. Header findings are listed but not scored: the fixtures are plain HTTP
on loopback, so "no HTTPS redirect" is always reported and TLS is not tested.

| Site | What it does |
|---|---|
| clean | 404 for everything except the homepage |
| forbidden | 403 for everything except the homepage |
| soft404-static | 200 with the same page for every URL |
| soft404-dynamic | 200 for every URL; the page echoes the path, carries a random nonce, and its navigation names phpMyAdmin, Adminer, Horizon, Telescope, Symfony, "Apache Server Status" and "PHP Version ... phpinfo" |
| redirect-login | every URL redirects to `/login`, whose page has the same navigation |
| decoys | 15 of the sensitive paths exist but hold harmless content (an HTML "restricted" page at `/.env`, `{}` at `/composer.json`, "XML-RPC is disabled" at `/xmlrpc.php`, a 401 JSON error at the users endpoint, and so on) |
| planted | all 29 exposures and endpoints are really there |

## Results

| Site | Requests | Planted | Found | False positives | Missed |
|---|---|---|---|---|---|
| clean | 31 | 0 | 0 | 0 | 0 |
| forbidden | 31 | 0 | 0 | 0 | 0 |
| soft404-static | 31 | 0 | 0 | 0 | 0 |
| soft404-dynamic | 31 | 0 | 8 | **8** | 0 |
| redirect-login | 60 (the cap) | 0 | 0 | 0 | 0 |
| decoys | 31 | 0 | 0 | 0 | 0 |
| planted | 33 | 29 | 29 | 0 | 0 |

- **29 of 29 planted exposures found, none missed.**
- **0 false positives on five of the six sites with nothing exposed,** including
  all 15 decoys.
- **8 false positives on `soft404-dynamic`:** `adminer-exposed`,
  `phpmyadmin-exposed`, `laravel-horizon`, `laravel-telescope`,
  `symfony-app-dev`, `server-status`, `exposed-phpinfo`, `exposed-info-php`.
  The probe spots a "200 for everything" site by fetching a random path and
  comparing later responses with it. A nonce that changes on every request
  defeats that comparison, and the checks that only look for a product name in
  the page then fire. Checks that validate structure (`.env`, `.git/HEAD`,
  `composer.lock`, SQL dumps, ZIP headers, the users endpoint, XML-RPC,
  Ignition) did not fire.
- **`redirect-login` used the whole request budget.** Each check costs two
  requests when everything redirects, so the 60-request cap was reached before
  every check had run. Nothing was reported, but the run was incomplete, and
  the only sign is a "request cap reached" note.
- **Only GET requests were sent** to every site.
- **No secret was echoed:** the planted `.env` values, the `wp-config` password
  and the REST usernames do not appear in the JSON or text output.
- **Without proof of ownership nothing active runs:** the planted site probed
  with the wrong token got 2 requests (the homepage and the ownership file) and
  reported no exposure or endpoint findings.

## What this does not show

- **Fixtures are not the internet.** Real sites sit behind CDNs, WAFs and rate
  limits, answer slowly, and build error pages in ways these seven do not.
- **No recall claim beyond these 29 paths.** The probe only requests a fixed
  list; a backup called `site-2026.zip` or a `.env.production` is not on it.
- **Version fingerprinting and feed matching are not measured here** (WordPress,
  plugin and PHP versions matched against advisories); see the unit tests.
- **TLS, HSTS and redirect checks are not exercised,** because the fixtures are
  plain HTTP on loopback.
- **No comparison** with OWASP ZAP, Nuclei or any other scanner.
