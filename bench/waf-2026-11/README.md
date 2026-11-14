# WAF rule benchmark, November 2026

`phpwarden rules` turns the feed's request signatures into ModSecurity or
nginx rules. This measures two things: how much ordinary traffic those rules
would block, and how many shapes of the real exploit requests they catch.
Run by the maintainer on 2026-11-14 (phpwarden 2.1.1 plus the unreleased
`--dry-run`/`--replay` flags). Rerun with `sh bench/waf-2026-11/run.sh`; that
run's output is in `results-2026-11-14.txt`.

**Short version: the first run of this benchmark found that the generated
rules blocked ordinary requests (1,146 of the 12,291 in the benign corpus
below), and that `rules --replay` did not show it. Both were fixed the same
day. After the fix the generated nginx and ModSecurity rules block 0 of the
12,291 and still catch every published exploit request.**

What changed: the rules are now built from the same conditions the log matcher
uses (`signature_regex` in `src/phpwarden/rules.py`), and `--replay` evaluates
those exact regexes, so a preview and the enforced rules cannot disagree.
The generated nginx rules were loaded into nginx (`nginx -t`) to confirm they
are valid. ModSecurity is still emulated here, not run.

| | Before the fix | After the fix |
|---|---|---|
| Benign requests blocked by the nginx rules | 1,146 of 12,291 | 0 of 12,291 |
| Benign requests blocked by the ModSecurity rules | 1,146 of 12,291 | 0 of 12,291 |
| Exploit shapes caught by the nginx rules | 21 of 28 | 22 of 28 |
| Exploit shapes caught by the ModSecurity rules | 24 of 28 | 25 of 28 |
| Published proof-of-concept requests caught | 8 of 8 | 8 of 8 |

`results-2026-11-14.txt` is the first run; `results-2026-11-14-after-fix.txt`
is the rerun. Sections 1 and 2 below describe the first run, kept as the
record of what was wrong. Still missed after the fix: php-cgi switches that
set no listed directive (`?-s`, `-d auto_append_file=`), and double-encoded
requests, which only matter if something in front of PHP decodes twice.

## How narrow this is

| | Count |
|---|---|
| PHP engine CVEs in the feed | 146 |
| Of those, with a request signature (so: with a WAF rule) | **3** |
| Composer and WordPress advisories in the feed | about 21,100 |
| Of those, with a request signature | **0** |

The three: CVE-2024-4577 and CVE-2012-1823 (php-cgi argument injection) and
CVE-2019-11043 (PHP-FPM `PATH_INFO` newline). This is three targeted rules,
not a web application firewall.

## Method

Nothing is sent to any server. `corpus.py` writes two files:

- **`benign.log`: 12,291 ordinary requests** in 14 categories. WordPress paths
  come from the file list of WordPress 7.1.4 (every `wp-admin/*.php`, every
  core script and stylesheet with a `?ver=`, the REST endpoints). The rest is
  generated with a fixed seed: Laravel and Symfony routes, searches, UTM and
  pagination queries, tokens, non-ASCII searches and slugs in about 20
  languages, GET forms carrying multi-line text, and searches and page slugs
  that *mention* `auto_prepend_file` or `allow_url_include`.
- **`attacks.tsv`: 28 request shapes** for the three CVEs: the published
  proof-of-concept requests plus case, encoding and double-encoding variants.

`evaluate.py` runs three matchers over both:

- **replay**: what `phpwarden rules --replay ACCESS_LOG` reports.
- **nginx**: the generated rules as nginx applies them (each
  `if ($request_uri ~* "...")` regex against the raw request target).
- **modsec**: the generated ModSecurity rules, *emulated* in Python against the
  raw target, the decoded target and each decoded argument. ModSecurity itself
  was not run.

The benign corpus is weighted towards awkward cases on purpose. The 9.3% below
is the share of *this corpus*, not a prediction for a real site.

## 1. False positives on benign requests (first run, before the fix)

| Category | Requests | replay | nginx rules | ModSecurity rules |
|---|---|---|---|---|
| WordPress files, assets, REST | 1,235 | 0 | 0 | 0 |
| Laravel and Symfony routes | 33 | 0 | 0 | 0 |
| ASCII searches | 3,000 | 0 | 0 | 0 |
| UTM, pagination, tokens, other encoded | 6,600 | 0 | 0 | 0 |
| Non-ASCII searches | 392 | 0 | **192** | **192** |
| Non-ASCII slugs | 147 | 0 | **72** | **72** |
| GET forms with multi-line text | 800 | 0 | **800** | **800** |
| Searches mentioning the directives | 72 | 0 | **72** | **72** |
| Page slugs mentioning the directives | 12 | 0 | **10** | **10** |
| **Total** | **12,291** | **0** | **1,146 (9.3%)** | **1,146 (9.3%)** |

Three causes, one per signature:

- **`%ad` (CVE-2024-4577).** The rule matches the text `%ad` anywhere in the
  URL. In UTF-8, "í" is `%C3%AD`, so any Spanish, Portuguese, Czech or Slovak
  URL with that letter is blocked: `/?s=categor%C3%ADa`, `/blog/pol%C3%ADtica-de-privacidad/`.
  The same byte appears in some Chinese and Korean characters (中, 국).
  264 requests.
- **`%0a` (CVE-2019-11043).** The exploit puts a newline in the *path*. The
  rule matches it anywhere, so every GET form that carries multi-line text in
  the *query* is blocked: `/contact?name=Ana&message=first+line%0Asecond+line`.
  800 requests.
- **`auto_prepend_file`, `allow_url_include`.** The rule matches the bare word,
  so a docs search (`/?s=auto_prepend_file`) or an article slug
  (`/blog/why-allow_url_include-is-dangerous/`) is blocked. The exploit always
  passes them as an assignment (`allow_url_include%3d1`). 82 requests.

`--replay` reports none of these because the log matcher behind it already has
the three fixes: it flags `%ad` only when the decoded bytes are not valid
UTF-8, `%0a` only in the path, and the directive names only when followed by
`=`. The generated rules do not have them. The full list of blocked requests
is written to `false-positives.tsv` in the work directory.

## 2. Detection of exploit request shapes (first run, before the fix)

| Technique | Shapes | replay | nginx rules | ModSecurity rules |
|---|---|---|---|---|
| Published proof-of-concept requests | 8 | 8 | 8 | 8 |
| Case variants (hex digits, directive names) | 4 | 4 | 4 | 4 |
| Encoding variants (`%20`, `%3D`, `%5f`, CRLF) | 7 | 6 | 6 | 7 |
| No directive (`?-s`, `?%ADs`) | 2 | 1 | 1 | 1 |
| A directive that is not on the list | 2 | 1 | 1 | 1 |
| Raw bytes as a log shows them (`\xAD`, `\x0A`) | 2 | 2 | 1 | 1 |
| Double-encoded | 3 | 0 | 0 | 2 |
| **Total** | **28** | **22** | **21** | **24** |

| CVE | Shapes | replay | nginx rules | ModSecurity rules |
|---|---|---|---|---|
| CVE-2024-4577 | 12 | 11 | 11 | 12 |
| CVE-2012-1823 | 9 | 5 | 5 | 6 |
| CVE-2019-11043 | 7 | 6 | 5 | 6 |

Every published proof-of-concept and every case variant is caught. The misses:

- **CVE-2012-1823 with no listed directive.** `/index.php?-s` (source
  disclosure) and `-d auto_append_file=...` are missed by all three: the
  signature is the two directive names, not the `?-` argument injection itself.
  CVE-2024-4577 does not have this gap because `%AD` is the signature.
- **Encoded underscores** (`allow%5Furl%5Finclude`): missed by replay and the
  nginx rule, which see the raw text. PHP-CGI decodes it, so this works as an
  attack. The ModSecurity rule catches it through the decoded arguments.
- **Double encoding** (`%25AD`, `%250A`): missed by replay and nginx. It is
  only an attack if something in front of PHP decodes twice, so these are
  listed for completeness.
- **Raw `\x0A`:** this is how a log shows the byte; it cannot occur in a real
  request line, so the nginx and ModSecurity misses here do not matter. The raw
  `\xAD` case does: a real request can carry the byte 0xAD unencoded, and a
  rule that looks for the text `%ad` will not see it. In this corpus the
  request was still caught through its directive names.

## What this does not show

- **Not real traffic.** The benign corpus is generated. It shows *which kinds*
  of request are blocked, not what share of a real site's requests would be.
- **Not a real WAF run.** nginx's regex is reproduced exactly; ModSecurity is
  emulated, without its transformations, body parsing or anomaly scoring.
- **Only GET request targets.** No request bodies, headers or cookies, although
  the ModSecurity rule also inspects POST arguments and `Content-Type`.
- **Three CVEs.** Nothing here says anything about protection against any
  other vulnerability in the feed.
- **Exploit shapes are built from the public advisories and proofs of concept,**
  not captured from attacks. A determined attacker has more variants than 28.
