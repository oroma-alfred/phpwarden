# Code scanner benchmark, November 2026

`phpwarden code` measured three ways: does it find the bugs in deliberately
vulnerable apps, how much does it report on clean, widely used code, and how
fast is it. Run by the maintainer on 2026-11-14 with phpwarden 2.1.1 plus the
unreleased `code` command (75 rules, 74 on by default). Rerun with
`sh bench/code-2026-11/run.sh`; the output of the latest run is in
`results-2026-11-14.txt`.

**Three runs.** The first run (`results-2026-11-14-before-fixes.txt`) found real
gaps in the scanner; they were fixed the same day without special-casing any
target (`results-2026-11-14-before-cross-file.txt`). The third run adds
cross-file taint tracking: functions, methods and file-level variables are
followed from one file to another. Numbers below are from the third run.

| | First run | After the fixes | With cross-file tracking |
|---|---|---|---|
| DVWA, vulnerable `low.php` found (of 8 in scope) | 4 | 5 | 5 |
| DVWA, fixed `impossible.php` wrongly flagged (of 8) | 1 | 0 | 0 |
| DVWA `medium.php` / `high.php` found (of 8) | 3 / 3 | 4 / 3 | 4 / 3 |
| Mutillidae II pages found (of 11) | 3 | 8 | **11** |
| WordPress: critical / high / medium / low | 1 / 10 / 13 / 17 | 1 / 6 / 16 / 4 | 0 / 7 / 20 / 4 |
| Laravel: critical / high / medium / low | 0 / 0 / 0 / 30 | 0 / 0 / 0 / 2 | 0 / 0 / 0 / 2 |
| Symfony: critical / high / medium / low | 0 / 0 / 0 / 4 | 0 / 0 / 0 / 2 | 0 / 0 / 0 / 2 |

**Short version: precision held, recall on Mutillidae went from 8 to 11 of
11.** High plus critical on 2.57 million lines of clean code stayed at 7. The
three DVWA misses remain: DVWA includes its `low.php` through a path built from
a variable, which the scanner does not resolve, and this benchmark scores
findings in `low.php` itself while the sink is in another file.

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
echoes `$html`). Cross-file tracking does follow variables through an
`include`, but only when the path is a literal (or a literal joined to
`__DIR__`, `dirname(__FILE__)` or a constant). DVWA includes the file through
`"vulnerabilities/fi/source/{$vulnerabilityFile}"`, a path chosen at run time,
so that flow stays invisible; and the score counts only findings in `low.php`.

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

**11 of 11** with cross-file tracking (8 before). The three SQL injections go
through two helper classes in other files: `user-info.php` calls
`$SQLQueryHandler->getUserAccount($name, $pass)`, which builds the SQL in
`classes/SQLQueryHandler.php` and passes it to
`$this->mMySQLHandler->executeQuery()`, which calls `doExecuteQuery()`, which
runs `$this->mMySQLConnection->query()` in `classes/MySQLHandler.php`. Each is
now reported at the call in the page, for example *"request data reaches
query() via getuseraccount() in src/classes/SQLQueryHandler.php:403"*. Two
things made it work besides the summaries themselves: methods are resolved by a
name the project defines only once, and a sanitiser behind an unrelated flag
(`if ($this->stopSQLInjection) { $p = escape($p); }`) no longer clears the
variable for the code after the `if`.

The run also reports 42 more findings elsewhere in Mutillidae (27 SQL
injection, 13 XSS, 1 SSRF, 1 XPath injection), nearly all through the same query
helper or the same security-level switches. Mutillidae is vulnerable by design;
a sample of ten was read by hand and all were real flows.

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
| WordPress 7.1.4 | 1,900 | 671,441 | 0 | 7 | 20 | 4 | 1.04 | 4.62 |
| Laravel v13.42.0 | 1,826 | 284,473 | 0 | 0 | 0 | 2 | 0.00 | 0.70 |
| Symfony v8.1.11 | 2,952 | 1,617,127 | 0 | 0 | 0 | 2 | 0.00 | 0.12 |

Across 2.57 million lines: 7 high or critical findings, all in WordPress, the
same total as before cross-file tracking (the first run had 11). All were read
by hand. **None is an exploitable vulnerability:**

| # | Where | Rule | Verdict |
|---|---|---|---|
| 1 | `wp-admin/plugins.php:53` | `path-read` | New with cross-file tracking: `$_REQUEST['plugin']` reaches a file read inside `get_plugin_data()` via `is_network_only_plugin()` in another file. A real flow, reachable only after `current_user_can('activate_plugin', $plugin)`; it reads plugin header fields. Admin-only. |
| 1 | `wp-includes/ms-files.php:99` | `path-readfile` | Guarded: `..` is stripped and the path is prefixed with the uploads directory. |
| 2 | `wp-admin/network/upgrade.php`, `wp-includes/https-detection.php` | `tls-verify-disabled` | Accurate and intentional (`'sslverify' => false` on requests to the site itself). |
| 3 | `class-phpass.php`, `pluggable.php` | `weak-hash-password` | Accurate and intentional: support for legacy MD5 password hashes. |

So: 5 accurate reports of something done on purpose, and 2 where the scanner
does not see the protection (a capability check in one case, a `..` filter in
the other). The previous `update.php:101` report (`include` of
`$_REQUEST['plugin']`) is gone: `check_admin_referer('activate-plugin_' .
$plugin)` binds the nonce to that exact value, and such a check is now treated
as authenticating it, the same reasoning as `hash_equals()`.

**What it took to keep precision with cross-file tracking.** The first
cross-file run reported 5 critical, 30 high and 180 medium findings on
WordPress. The rules that brought it back, all general:
- a function is exported to other files as "returns request data" only when
  every `return` in it does, and only for direct request input
  (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_FILES`, request objects), not the
  current URL from `$_SERVER` (`add_query_arg()` and friends);
- a name is resolved across files only when the project defines it once, or
  identically everywhere;
- an object property's taint is used inside its own class, never as part of a
  method's return value, and never copied from one property to another;
- WordPress validators are understood: `validate_file()`, `validate_plugin()`,
  `is_wp_error(validate_*())`, `validate_file_to_edit()`, and comparisons
  written as `0 !== validate_file($f)`;
- `$upload['tmp_name']` / `['size']` / `['error']` of a `$_FILES` entry are
  PHP's own values, not the client's;
- `for ($i = 0; ...)` resets `$i`;
- variables flow from an included file into the file that includes it, not the
  other way round (template variable names are reused too freely for that). The four false positives of the first run are gone:
`setup-config.php` (the prefix is rejected by `preg_match('|[^a-z0-9_]|i')`
followed by `wp_die()`, now understood as a guard) and three in the Requests
library's `Curl.php` (TLS checks switched off inside the caller's own
`verify === false` option check).

WordPress has 20 medium findings (16 before cross-file tracking): 8
`wp_redirect()` calls built from request or `$_SERVER` values, 8 `echo` and 2
`printf` of request-derived data, 2 `rand()` used for a nonce or fallback salt.
The four new ones were read: `ajax-actions.php` echoes `do_shortcode()` of a
posted shortcode (real flow, capability-checked), `network/users.php` passes
`$_POST['allusers']` to `confirm_delete_users()`, which prints the IDs with
`printf()` in another file (real flow, network admin only), and
`import.php:215` echoes a row built partly from importer data (not traced to
the end).

The noisy rule of the first run, `unserialize-no-allowed-classes` (43 of its
51 low findings), is now opt-in: it runs only when selected by rule id or with
every rule enabled.

## 4. Speed

| Target | Files | Time | Files per second |
|---|---|---|---|
| DVWA | 169 | 0.19 s | 874 |
| Mutillidae II | 294 | 0.30 s | 989 |
| WordPress | 1,900 | 9.1 s | 209 |
| Laravel | 1,826 | 2.6 s | 702 |
| Symfony | 2,952 | 6.3 s | 469 |

Cross-file tracking costs time: every file is scanned once, then files that
call a function whose summary changed are scanned again, for up to three
rounds (WordPress 3.9 s → 9.1 s, Laravel 1.4 s → 2.6 s, Symfony 4.9 s →
6.3 s). A file is rescanned only when the change can matter there: it has
request input, or one of its own functions calls the changed name.
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
- **Still not followed:** includes whose path is built at run time, chains of
  more than about three helpers across files (three rounds), method calls on a
  name defined in more than one class, properties shared between classes, and
  closures passed as callbacks.
- **Guards are recognised by shape,** not proven: `is_numeric`, `ctype_*`,
  strict `in_array` against literals, anchored whitelist `preg_match`, and
  `hash_equals`, when the failing branch exits or the check wraps the sink.
  Other validation is not understood and can still produce false positives.
- **Only high and critical findings were triaged by hand.** The medium ones in
  WordPress were read but not each verified.
- **Numbers move** with every rule change; the commit hashes above pin the
  targets, not the scanner.

## AST engine (stage B, 2026-11-14)

`phpwarden.sast` replaces the token engine's taint analysis with a
whole-program one on the parsed AST: types resolve method calls, every
function gets a summary (parameters to sinks, parameters and request data to
the return value, parameters to `$this` properties), summaries are computed
callee-first over the call graph's strongly connected components and iterated
to a fixed point, and framework models supply Laravel, Symfony and WordPress
sources, sinks and entry points. Every finding carries a trace (source, hops,
sink), also emitted as SARIF `codeFlows`.

It is opt-in: `code.scan_project(path, engine="ast")` (or `"auto"`, which
keeps token-engine taint findings for files the parser could not read). The
default stays `engine="tokens"`, because the AST engine adds new high/critical
findings on clean code (below), and the rule was that the default only changes
with better recall *and* no precision loss. Pattern rules (weak hashes, TLS,
cookies...) come from the token engine in every mode.

Same targets, same commits, same `score.py`:

| | token engine | AST engine |
|---|---|---|
| DVWA low.php: in-scope types flagged | 5/8 | **7/8** (+fi, +xss_r) |
| DVWA impossible.php: wrongly flagged | 0/8 | 0/8 |
| DVWA medium.php / high.php flagged | 4/8 / 3/8 | **6/8 / 5/8** |
| Mutillidae: pages flagged | 11/11 | 11/11 |
| WordPress high+critical | 7 | 11 |
| Laravel high+critical | 0 | 0 |
| Symfony high+critical | 0 | 4 |
| Time: DVWA / Mutillidae | 0.1 s / 0.4 s | 0.3 s / 0.9 s |
| Time: WordPress / Laravel / Symfony | 8.8 s / 2.4 s / 6.0 s | 17.6 s / 12.3 s / 43.1 s |

The AST times include the token engine (pattern rules) plus parsing and
modelling the whole project; Symfony is 1.6 M lines.

New high/critical findings on clean code, triaged (all false positives or by
design; none is a vulnerability):

- WordPress `ajax-actions.php:1744` (unserialize): meta values from an
  admin-only, nonce-checked AJAX handler are shown through `_list_meta_row()`,
  which calls `maybe_unserialize()`. Admin-gated, and WordPress stores meta
  serialized by design.
- WordPress `class-file-upload-upgrader.php:153` (path-delete): the package
  path is what `wp_handle_upload()` returns: the upload moved to a sanitized,
  unique name. The engine sees `$_FILES[$form]` go in and a path come out.
- WordPress `class-wp-links-list-table.php:76` and `functions.php:1147/1153`
  (sql-wpdb): request data reaches `get_bookmarks()`, which escapes the search
  term and whitelists ordering. The engine is field-sensitive inside a
  function but not across calls, so an array with one tainted key taints all
  keys in the callee.
- Symfony `HttpClientKernel.php:53` (ssrf-http-client): the kernel exists to
  forward the request to an HTTP client; by design.
- Symfony `Request.php:2169`, `FormEncodedBodyExtractor.php:40`,
  `QueryAccessTokenExtractor.php:40` (ssrf-http-client): the token or host
  ends up in the query string of a URL whose host is configured, not chosen
  by the request.

Precision measures that got it there, each kept because it removed false
positives without losing a recall target: unmodelled validation hides in deep
chains, so parameter-to-sink flows are kept for at most 2 calls (3 for SQL
query wrappers, 1 for paths, includes, unserialize and HTTP clients, 0 for
dynamic calls); return flows for at most 3 functions; untyped `$x->m()` is
followed only when at most two classes define `m`; property stores fed from
outside the class are not shared between instances; known sanitizers win over
a project's own definition of the same name (WordPress defines `esc_sql`);
an included file contributes only what it read from the request itself.

Not yet handled by the AST engine: field sensitivity across calls (the
WordPress cases above), callbacks given as closures to unknown functions,
URL-prefix reasoning for SSRF (a fixed host before the tainted part), and
anything the token engine's ad-hoc wrapper rules catch that a 2-call limit
cuts off.

## Stage C (2026-11-14): AST engine precision, layer-5 rules

Full output: `results-2026-11-14-stage-c.txt`.

| target | tokens | auto (stage B) | auto (stage C) |
|---|---|---|---|
| DVWA low (of 8) | 5 | 7 | 7 |
| DVWA medium / high | 4 / 3 | 6 / 5 | 6 / 5 |
| DVWA impossible wrongly flagged | 0 | 0 | 0 |
| Mutillidae (of 11) | 11 | 11 | 11 |
| WordPress / Laravel / Symfony high+critical | 7 / 0 / 0 | 16 / 0 / 0 | 7 / 0 / 0 |
| time WP / Laravel / Symfony (s) | 9.1 / 2.5 / 6.3 | | 14.0 / 6.1 / 28.6 |

Precision fixes: per-key array taint across calls, switch/in_array whitelists,
local property writes preferred over the class-wide union, framework
sanitising return values, SSRF only when the value controls scheme/host/port,
admin-only flows lowered one level with context `requires-authenticated-admin`.

New AST rules (medium unless stated), all with 0 findings on WordPress, Laravel
and Symfony core: second-order-injection (high), wp-admin-post-no-nonce,
laravel-route-no-auth, symfony-route-no-auth, laravel-idor-hint,
laravel-csrf-excluded; unserialize-tainted escalates to critical when
composer.lock has a known gadget-chain package.

Default engine stays `tokens`: the benchmark gates pass, but 19 checks in
tests/test_code.py encode token-engine behaviour (message wording "via f()",
reporting at the caller rather than in library files, PHP_SELF as a source,
non-strict in_array not a guard, global-variable taint, etc.) that the AST engine
does not reproduce yet.

## Default engine (2026-11-14)

`phpwarden code` now uses the AST engine by default (`engine="auto"`: the whole-program
taint engine for files it parses, the token engine for files it cannot, and the token
engine's pattern rules everywhere). `PHPWARDEN_CODE_ENGINE=tokens` restores the old engine.

To get there, the AST engine was brought in line with the token engine's precision rules:
int/float/bool-typed parameters carry no injectable data; `pathinfo(..., PATHINFO_EXTENSION)`
cannot lead a path; a `preg_replace()` that strips everything outside a safe character class
cleans the value; `isset($allowed[$v])` with a fallback assignment is an allowlist; a function
counts as returning request data only if every return does, and never for `$_SERVER` values;
`$_SERVER['PHP_SELF']`/`PATH_INFO` reach HTML; closures see `use ($x)` values; `global $x`
set in a function is visible at file scope; `curl_setopt(..., CURLOPT_URL, ...)` is an SSRF
sink; a `$wpdb->query()` whose SQL starts with SELECT/SHOW/DESCRIBE/EXPLAIN is not a write.
Values returned by a helper are reported where they are used, with "via helper() in
file:line"; flows through an include are still reported where the included file reads the
request. Loose `in_array()` is a whitelist only against non-numeric string literals.

Gates with the new default (`results-2026-11-14-default-auto.txt`):

| | token engine | default (auto) |
|---|---|---|
| DVWA low.php flagged (of 8) | 5 | **7** |
| DVWA medium / high | 4 / 3 | **6 / 5** |
| DVWA impossible.php wrongly flagged | 0 | **0** |
| Mutillidae (of 11) | 11 | **11** |
| Clean WordPress / Laravel / Symfony high+critical | 7 / 0 / 0 | **7 / 0 / 0** |
| Time: DVWA / Mutillidae / WordPress / Laravel / Symfony | 0.3 / 0.7 / 9.1 / 2.5 / 6.3 s | 0.4 / 1.1 / 16.7 / 4.8 / 39.0 s |

The default engine is slower: about 2x on WordPress and Laravel and 6x on Symfony
(1.6M lines), where parsing and the whole-program call graph dominate.
`phpwarden code --list-rules` lists 89 rules with the default engine (75 with the token engine).

## Fixes after the comparison benchmark (2026-11-14)

`bench/sast-compare-2026-11` (phpwarden against Semgrep and Psalm) exposed four
gaps; all are fixed, with regression tests, and the gates still hold. Results:
`results-2026-11-14-stage-d-fixes.txt` (default engine, `auto`).

| | before (`06d4700`) | after |
|---|---|---|
| DVWA low.php flagged (of 8) | 7 | 7 |
| DVWA medium / high flagged | 6 / 5 | **7 / 6** |
| DVWA impossible.php wrongly flagged | 0 | 0 |
| Mutillidae (of 11) | 11 | 11 |
| Clean WordPress / Laravel / Symfony high+critical | 7 / 0 / 0 | 7 / 0 / 0 |
| Runtime WordPress / Laravel / Symfony | 16.7 / 4.8 / 39.0 s | 14.3 / 5.2 / 15.9 s |

- **Session values as a second-order source:** `$_SESSION['k'] = <request data>`
  anywhere in the project makes reads of `$_SESSION['k']` (same literal key) a
  source; the finding keeps the sink's rule and carries the context
  "stored in session at file:line". Dynamic keys do nothing. This finds DVWA's
  SQL injection at `high`.
- **Client MIME type is not validation:** `$_FILES[..]['type']` comparisons no
  longer count as an upload check (also in the token engine); real checks are an
  extension allow-list from the file name, `getimagesize`/`finfo`/
  `mime_content_type`, `wp_check_filetype(_and_ext)`, or a Laravel `mimes:`/
  `image` rule. This finds DVWA upload at `medium`; the fixed version stays clean.
- **Reflected XSS through an array element in another file** and **the fixed
  file-inclusion allow-list** were already right at `06d4700`; both now have
  regression tests.
- **Speed:** the parser skips data-only files (no variables, declarations,
  includes or output once strings and comments are removed: translation and emoji
  tables), the token pass runs in a second process while the AST is built, and
  garbage collection pauses during the analysis. Symfony went from 39 s to 16 s
  (1.3 times the token engine on the same run).

Still missed: DVWA stored XSS (database rows are not sources) and the `high`
upload level (extension allow-list plus `getimagesize`, exploitable only with a
second bug).

