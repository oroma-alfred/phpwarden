# Code scanner benchmark, November 2026

`phpwarden code` measured three ways: does it find the bugs in deliberately
vulnerable apps, how much does it report on clean, widely used code, and how
fast is it. Run by the maintainer on 2026-11-14 with phpwarden 2.1.1 plus the
unreleased `code` command (75 rules, 74 on by default). Rerun with
`sh bench/code-2026-11/run.sh`; the output of that run is in
`results-2026-11-14.txt`.

**Two runs.** The first run (`results-2026-11-14-before-fixes.txt`) found real
gaps in the scanner. They were fixed the same day, without special-casing any
target, and the numbers below are from the rerun. Before and after:

| | First run | After the fixes |
|---|---|---|
| DVWA, vulnerable `low.php` found (of 8 in scope) | 4 | 5 |
| DVWA, fixed `impossible.php` wrongly flagged (of 8) | 1 | 0 |
| DVWA `medium.php` / `high.php` found (of 8) | 3 / 3 | 4 / 3 |
| Mutillidae II pages found (of 11) | 3 | 8 |
| WordPress: critical / high / medium / low | 1 / 10 / 13 / 17 | 1 / 6 / 16 / 4 |
| Laravel: critical / high / medium / low | 0 / 0 / 0 / 30 | 0 / 0 / 0 / 2 |
| Symfony: critical / high / medium / low | 0 / 0 / 0 / 4 | 0 / 0 / 0 / 2 |

**Short version: precision is good; recall is better than it was but still
limited by one design choice.** The scanner does not follow data from one file
to another, and that accounts for every remaining miss.

## Targets (pinned by commit)

| Target | Version | Commit |
|---|---|---|
| DVWA | master, 2026-10-18 | `a1978a2fed19` |
| OWASP Mutillidae II | main, 2026-09-24 | `126a1fdb4ff9` |
| WordPress | 7.1.4 | `db96f5eaa77a` |
| Laravel framework | v13.42.0 | `f5c01f6b6380` |
| Symfony | v8.1.11 | `eca3b7b6bd3a` |

Third-party code is cloned to a temp directory by `run.sh`, never into this
repository. Default scanner settings: `vendor/`, `node_modules/`, `tests/` and
`*Test.php` are skipped.

## 1. Recall on DVWA

DVWA ships a vulnerable `low.php` and a fixed `impossible.php` for each
vulnerability type. A finding of the matching rule category in `low.php` is a
hit; the same in `impossible.php` is a false positive. Eight types are in
scope (request data reaching a dangerous function); the other eleven (CSRF,
brute force, CAPTCHA, CSP, DOM XSS, weak session IDs and so on) are logic or
browser-side problems this kind of scanner does not attempt.

| Type | `low.php` (vulnerable) | `impossible.php` (fixed) |
|---|---|---|
| SQL injection | found (`sql-db-query`, `sql-mysqli-query`) | clean |
| SQL injection, blind | found (`sql-db-query`, `sql-mysqli-query`) | clean |
| Command injection | found (`cmd-shell-exec`) | clean |
| Open redirect | found (`redirect-header`) | clean |
| Unrestricted upload | found (`upload-unrestricted`) | clean |
| File inclusion | **missed** | clean |
| Reflected XSS | **missed** | clean |
| Stored XSS | **missed** | clean |

**5 of 8 found, 0 of 8 fixed files wrongly flagged.** On the partly filtered
`medium.php` and `high.php` variants (still vulnerable): 4 of 8 and 3 of 8.

Why three are still missed: DVWA reads the input in `source/low.php` and uses
it in a different file (`fi/index.php` does the `include`; the page template
echoes `$html`). The scanner does not follow data across files.

What the fixes changed here:
- **Unrestricted upload** is found by a new rule, `upload-unrestricted`: the
  client's file name reaches `move_uploaded_file()` and nothing in the function
  restricts the file type. `basename()` alone does not count.
- **SQL injection, `medium.php`** is found: a value that went through
  `mysqli_real_escape_string()` and is then used *unquoted* in the query is
  still injectable, and is now reported.
- **The false positive is gone:** `exec/source/impossible.php` checks every
  part of the IP with `is_numeric()` in the `if` that wraps the command. Such
  validation guards are now understood.

## 2. Recall on Mutillidae II

Eleven pages whose vulnerability the project documents itself:

| Page | Class | Result |
|---|---|---|
| `text-file-viewer.php` | remote file read | found (`path-read`) |
| `xml-validator.php` | XML external entity | found (`xxe-entity-loader`) |
| `upload-file.php` | unrestricted upload | found (`path-move-upload`) |
| `dns-lookup.php` | command injection | found (`cmd-shell-exec`) |
| `echo.php` | command injection | found (`cmd-shell-exec`) |
| `index.php` | local file inclusion | found (`include-tainted`) |
| `source-viewer.php` | arbitrary file read | found (`path-readfile`) |
| `redirectandlog.php` | open redirect | found as `xss-echo` (the redirect is a `<meta refresh>` tag built from the request, not a `Location` header) |
| `user-info.php` | SQL injection | missed |
| `includes/process-login-attempt.php` | SQL injection | missed |
| `add-to-your-blog.php` | SQL injection, stored XSS | missed |

**8 of 11.** The three misses have one cause: the queries go through a helper
class in another file (`$SQLQueryHandler->getUserAccount($name)` builds the
SQL in `classes/SQLQueryHandler.php`). The scanner follows a value through one
function or method call **in the same file**, not across files. That is the
main design limit.

What the fixes changed here (the first run found 3 of 11):
- **Assignments inside expressions are tracked,** including both branches of a
  ternary: `$c ? $host = $_POST["h"] : $host = $_REQUEST["h"];`.
- **Code inside `switch`/`case` blocks is analysed,** as are `match` and the
  `if (): ... endif;` template syntax. Mutillidae switches on its security
  level almost everywhere.
- **Branches no longer cancel each other:** a value cleaned in one `case`,
  `elseif` or `else` branch stays reported for the branch that did not clean it.

## 3. Findings on clean code

| Target | Files | Lines | Critical | High | Medium | Low | High+critical per 100k lines | All per 100k lines |
|---|---|---|---|---|---|---|---|---|
| WordPress 7.1.4 | 1,900 | 671,441 | 1 | 6 | 16 | 4 | 1.04 | 4.02 |
| Laravel v13.42.0 | 1,826 | 284,473 | 0 | 0 | 0 | 2 | 0.00 | 0.70 |
| Symfony v8.1.11 | 2,952 | 1,617,127 | 0 | 0 | 0 | 2 | 0.00 | 0.12 |

Across 2.57 million lines: 7 high or critical findings, all in WordPress (the
first run had 11). All were read by hand. **None is an exploitable
vulnerability:**

| # | Where | Rule | Verdict |
|---|---|---|---|
| 1 | `wp-admin/update.php:101` | `include-tainted` | Real data flow (`$_REQUEST['plugin']` reaches `include`), but behind `current_user_can('update_plugins')` and a nonce check. Guarded by design. |
| 1 | `wp-includes/ms-files.php:99` | `path-readfile` | Guarded: `..` is stripped and the path is prefixed with the uploads directory. |
| 2 | `wp-admin/network/upgrade.php`, `wp-includes/https-detection.php` | `tls-verify-disabled` | Accurate and intentional (`'sslverify' => false` on requests to the site itself). |
| 3 | `class-phpass.php`, `pluggable.php` | `weak-hash-password` | Accurate and intentional: support for legacy MD5 password hashes. |

So: 5 accurate reports of something done on purpose, and 2 where the scanner
does not see the protection (a capability check in one case, a `..` filter in
the other). The four false positives of the first run are gone:
`setup-config.php` (the prefix is rejected by `preg_match('|[^a-z0-9_]|i')`
followed by `wp_die()`, now understood as a guard) and three in the Requests
library's `Curl.php` (TLS checks switched off inside the caller's own
`verify === false` option check).

The 16 medium findings in WordPress went up from 13, because code the first
run skipped is now analysed. Not each verified: 8 `wp_redirect()` calls built
from request or `$_SERVER` values (one of them, `authorize-application.php`,
is commented in the source as deliberately not using `wp_safe_redirect()`),
6 `echo` of request-derived data (admin screens and JSONP output), 2 `rand()`
used for a nonce or fallback salt.

The noisy rule of the first run, `unserialize-no-allowed-classes` (43 of its
51 low findings), is now opt-in: it runs only when selected by rule id or with
every rule enabled.

## 4. Speed

| Target | Files | Time | Files per second |
|---|---|---|---|
| DVWA | 169 | 0.19 s | 874 |
| Mutillidae II | 294 | 0.30 s | 989 |
| WordPress | 1,900 | 3.87 s | 490 |
| Laravel | 1,826 | 1.36 s | 1,340 |
| Symfony | 2,952 | 4.93 s | 599 |

Slower than the first run (WordPress took 2.60 s): files that define wrapper
functions are read twice, so a wrapper defined below its call is still found.
One run each on an Apple-silicon laptop, single process, including Python
start-up. No crashes on any target.

## What this does not show

- **It is not a comparison.** No other tool (PHPStan, Psalm, Semgrep) was run
  on the same targets.
- **Two vulnerable apps is a small sample,** and both are teaching apps written
  in an old procedural style. Modern framework code hides input behind request
  objects and helpers, which this scanner follows even less well.
- **"Clean" codebases are not ground truth.** Zero findings in Laravel means the
  rules were quiet, not that Laravel has no bugs.
- **Still not followed:** data that crosses a file boundary, a wrapper of a
  wrapper (only one level is followed), values stored in object properties,
  and closures passed as callbacks.
- **Guards are recognised by shape,** not proven: `is_numeric`, `ctype_*`,
  strict `in_array` against literals, anchored whitelist `preg_match`, and
  `hash_equals`, when the failing branch exits or the check wraps the sink.
  Other validation is not understood and can still produce false positives.
- **Only high and critical findings were triaged by hand.** The medium ones in
  WordPress were read but not each verified.
- **Numbers move** with every rule change; the commit hashes above pin the
  targets, not the scanner.
