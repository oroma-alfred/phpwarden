# phpwarden code vs Semgrep and Psalm, November 2026

The same pinned PHP codebases, run through four analysers, scored against the
same ground truth. Run by the maintainer on 2026-11-14; everything is
reproducible with `sh bench/sast-compare-2026-11/run.sh` and the raw output of
that run is in `results-2026-11-14.txt`. The phpwarden rows were rerun the
same day after fixing what the first run exposed; the first run (phpwarden at
commit `4140209`) is kept in `results-2026-11-14-at-4140209.txt`, and its
weaknesses are listed under "Fixed since the first run". We make phpwarden, so read our numbers
with that in mind: the scripts, the category mapping and every hand-triage
verdict (`triage.json`) are published so you can check them.

**Short version.**

- On the two deliberately vulnerable apps, phpwarden found the most: all 11
  documented Mutillidae vulnerabilities (Psalm 8, Semgrep 4) and 7/7/6 of the 8
  in-scope DVWA types at low/medium/high with its default whole-program engine
  (Psalm 5/3/4, Semgrep 3/2/3), with no wrong flag on DVWA's fixed versions
  (Semgrep 1, Psalm 2).
- On clean framework code, phpwarden was by far the quietest: 7 high findings
  in all of WordPress core (5 of them accurate reports of intentional patterns,
  2 false positives) and none in Laravel or Symfony. Semgrep raised 173 in
  WordPress, Psalm 442 in WordPress, 590 in Laravel and 985 in Symfony; every
  sampled one was a false positive or intended behaviour.
- phpwarden was the fastest tool on DVWA, Mutillidae and WordPress. On Laravel
  (7.1 s against 4.3 s) and Symfony (15.1 s against 9.4 s) Semgrep was faster.
- **Where phpwarden loses:** no tool, phpwarden included, finds DVWA's stored
  XSS (it goes through the database), and phpwarden misses DVWA's `high` upload
  level and one `high` filter case. Details below.
- **Snyk Code is not in this comparison.** It needs an account and a logged-in
  CLI, so we could not run it. The script supports it (see "Running Snyk Code").

## What was compared

| Tool | Version | How it was run |
|---|---|---|
| phpwarden, token engine | this repo after commit `06d4700` (the commit that adds session sources, the upload MIME fix and the speed work) | `PHPWARDEN_CODE_ENGINE=tokens phpwarden code TARGET --json` |
| phpwarden, whole-program engine (the default since `06d4700`) | same | `PHPWARDEN_CODE_ENGINE=auto phpwarden code TARGET --json` |
| Semgrep OSS | 1.185.0 | `semgrep scan --config p/php --config p/owasp-top-ten --metrics=off`, excluding `tests/`, `Tests/` and `vendor/` |
| Psalm | 7.5.0 | `psalm --taint-analysis` with a minimal config that excludes `vendor/` and test folders at any depth; SARIF report (it carries Psalm's taint traces) |

Semgrep's registry packs are not versioned, so the exact files used are kept by
`run.sh` with their SHA-256 (`p/php`: `45f37e32…6bd84`, 24 rules;
`p/owasp-top-ten`: `5f344573…a3a1`, 560 rules across languages, of which only
findings in PHP files are scored).

Psalm needs the code's dependencies to resolve classes. Laravel's were installed
with `composer install --no-scripts --ignore-platform-reqs`. The Symfony
monorepo's could not be resolved by Composer, so Psalm ran on Symfony with only
the project's own autoloader (`composer dump-autoload`); its results there are
for that setup. Each tool was configured the way its documentation recommends
for PHP security scanning; nothing was tuned for these targets.

**Targets** (pinned by commit, the same as `bench/code-2026-11`): DVWA
`a1978a2f`, Mutillidae II `126a1fdb`, WordPress 7.1.4 `db96f5ea`, Laravel
framework v13.42.0 `f5c01f6b`, Symfony v8.1.11 `eca3b7b6`.

## How findings are compared

Every tool's output is normalised to a file, a line, one or more vulnerability
categories, whether it is high severity, and the files on its data-flow trace
when the tool reports one. Categories: SQL injection, command injection, code
execution, file inclusion, path traversal / file access, XSS, SSRF,
deserialization, open redirect, XXE, unrestricted upload. The mapping:

| Tool | Mapping |
|---|---|
| phpwarden | the rule's own category (`code --list-rules`); `path-move-upload`/`upload-unrestricted` count as upload |
| Semgrep | the CWE in the rule's metadata (CWE-89 SQLi, 78/77 command, 94/95 code, 98 inclusion, 22/23/73 path, 79 XSS, 918 SSRF, 502 deserialization, 601 redirect, 611 XXE, 434 upload). `tainted-filename` is labelled CWE-918 but fires on request data reaching any file-opening function, so it counts for path, inclusion and SSRF |
| Psalm | issue type: TaintedSql, TaintedShell, TaintedEval/TaintedCallable (code), TaintedInclude, TaintedFile (path), TaintedHtml/TaintedTextWithQuotes (XSS), TaintedSSRF, TaintedUnserialize, TaintedHeader (redirect), TaintedXpath (XXE) |

"High severity" means phpwarden critical/high, Semgrep `ERROR`, and every Psalm
`Tainted*` issue (Psalm reports them all as errors).

**DVWA** has, for each vulnerability type, deliberately vulnerable `low`,
`medium` and `high` versions and a fixed `impossible` version. A finding counts
as found when it is in the right category and either sits in
`vulnerabilities/<type>/source/<level>.php` or its reported trace passes through
that file (DVWA reads the input there and often prints it from `index.php`). The
same match on `impossible.php` is a wrong flag. Eight types are in scope for
this kind of tool: SQL injection, blind SQL injection, command injection, file
inclusion, reflected and stored XSS, upload, open redirect.

**Mutillidae II**: the 11 pages whose vulnerability the project documents.

**Clean code**: WordPress core, Laravel and Symfony are not free of bugs, but a
high-severity finding there is far more likely noise than a new vulnerability.
Every high finding is counted, and a seeded random sample of up to 15 per tool
and target was read by hand.

## Results

### Deliberately vulnerable apps

DVWA, found at low / medium / high (`x` found, `.` missed), and wrong flags on
the fixed version:

| Type | phpwarden tokens | phpwarden whole-program | Semgrep | Psalm |
|---|---|---|---|---|
| SQL injection | xx. | xxx | x.. | x.. |
| blind SQL injection | xxx | xxx | xxx | x.x |
| command injection | xxx | xxx | xxx, **wrong flag** | xxx, **wrong flag** |
| file inclusion | ... | xxx | ..x | ... |
| reflected XSS | ... | xxx | ... | ... |
| stored XSS | ... | ... | ... | ... |
| upload | xx. | xx. | ... | xxx, **wrong flag** |
| open redirect | xxx | xxx | ... | xxx |
| **found (of 8)** | 5 / 5 / 3 | **7 / 7 / 6** | 3 / 2 / 3 | 5 / 3 / 4 |
| **wrong flags (of 8)** | **0** | **0** | 1 | 2 |

The two benchmarks score DVWA differently: this one counts a level when a finding
of the matching category is in that level's file, `bench/code-2026-11` counts
relevant rule ids on the level file with its own list of in-scope types. That is
why the first run disagreed (6/5/4 here, 7/6/5 there); after the fixes both read
7/7/6.

Mutillidae, documented vulnerable pages found:

| | phpwarden tokens | phpwarden whole-program | Semgrep | Psalm |
|---|---|---|---|---|
| **found (of 11)** | **11** | **11** | 4 | 8 |

Semgrep found the two command injections and the two file reads. Psalm missed
both SQL injections that go through Mutillidae's helper class
(`user-info.php`, `process-login-attempt.php`) and the XXE. Per page:
`results-2026-11-14.txt`, section 2.

### Clean framework code: high-severity findings

| Target | Lines | phpwarden tokens | phpwarden whole-program | Semgrep | Psalm |
|---|---|---|---|---|---|
| WordPress 7.1.4 | 671,441 | 7 (1.0 per 100k) | 7 (1.0) | 173 (25.8) | 442 (65.8) |
| Laravel v13.42.0 | 284,473 | 0 | 0 | 0 | 590 (207.4) |
| Symfony v8.1.11 | 1,617,127 | 0 | 0 | 2 (0.1) | 985 (60.9) |

Hand triage of the samples (verdicts and notes in `triage.json`):

| Target | Tool | Sampled | True vulnerability | False positive | Intended behaviour |
|---|---|---|---|---|---|
| WordPress | phpwarden tokens | 7 (all) | 0 | 2 | 5 |
| WordPress | phpwarden whole-program | 7 (all) | 0 | 2 | 5 |
| WordPress | Semgrep | 15 of 173 | 0 | 15 | 0 |
| WordPress | Psalm | 15 of 442 | 0 | 15 | 0 |
| Laravel | Psalm | 15 of 590 | 0 | 15 | 0 |
| Symfony | Semgrep | 2 (all) | 0 | 0 | 2 |
| Symfony | Psalm | 15 of 985 | 0 | 13 | 2 |

phpwarden's "intended behaviour" findings are `sslverify => false` on WordPress's
requests to itself and MD5 kept for legacy password hashes: accurate, but not
vulnerabilities. Its two false positives in each engine: `ms-files.php` (the
path has `..` removed and is checked with `is_file()`) and either
`plugins.php:53` (tokens; the plugin name was validated) or an admin-only,
nonce-checked AJAX handler (whole-program). Semgrep's WordPress findings were
mostly `echoed-request` on values that are escaped, cast to int or internal, and
`tainted-sql-string` matching `wp_nonce_url()` and `check_admin_referer()`.
Psalm's were framework internals: class names, callbacks and paths that come
from configuration or code, which its taint model treats as user input.

### Runtime (wall seconds, this laptop)

| Target | phpwarden tokens | phpwarden whole-program | Semgrep | Psalm |
|---|---|---|---|---|
| DVWA | 0.4 | 0.7 | 3.1 | 1.5 |
| Mutillidae | 0.9 | 1.9 | 5.8 | 4.4 |
| WordPress | 17.3 | 14.0 | 53.4 | 19.5 |
| Laravel | 4.9 | 7.1 | 4.3 | 24.9 |
| Symfony | 12.3 | 15.1 | 9.4 | 37.4 |

phpwarden's rows were timed in the second run, on a busier machine than the
first (the token engine took 6.2 s on Symfony then, 12.3 s now); Semgrep's and
Psalm's are from the first run.

Psalm's times exclude installing dependencies.

## Where phpwarden loses

- **DVWA stored XSS: missed** (so is every other tool). The input is written to
  the database in one request and printed from a `SELECT` in another
  (`dvwaGuestbook()`); phpwarden does not treat database rows as sources.
- **DVWA upload, `high`: missed.** The level checks the extension taken from the
  client file name against `jpg`/`jpeg`/`png` and runs `getimagesize()` on the
  upload. phpwarden accepts that as validation; DVWA's attack for this level is
  an image with PHP inside, executed through a separate file inclusion bug.
- **Speed on very large code:** 15 s on the 1.6-million-line Symfony monorepo,
  1.6 times Semgrep, and slower than Semgrep on Laravel.

### Fixed since the first run (phpwarden at `4140209`)

- **DVWA file inclusion, fixed version, wrongly flagged:** a non-strict
  `in_array()` against a literal list of non-numeric names is now an allow-list.
- **DVWA reflected XSS, missed:** the value is followed through `$page['body']`
  into the echo helper in another file.
- **DVWA SQL injection at `high`, missed:** a session key written from request
  data (`$_SESSION['id'] = $_POST['id']`) is a source wherever the same key is
  read, reported with "stored in session at file:line".
- **DVWA upload at `medium`, missed:** the client-supplied MIME type
  (`$_FILES[..]['type']`) no longer counts as validation.
- **Speed:** Symfony 30 s to 15 s (data-only files are not parsed, the token pass
  runs in a second process, and garbage collection pauses during the analysis).

## What this does not show

- Snyk Code, CodeQL, SonarQube and commercial analysers are not included.
- Two deliberately vulnerable apps are a small recall sample, and both are
  written in an old, procedural PHP style. Framework-style apps (Laravel
  controllers, Symfony services, WordPress plugins) are measured only for noise
  here, not for recall.
- Clean-code noise is measured on frameworks, which are libraries: much of their
  code is never reached from a request. An application built on them would give
  different numbers.
- Psalm's taint analysis is designed to be tuned with annotations
  (`@psalm-taint-escape` and similar) and a baseline; this run uses it as
  installed, which is how a first-time user meets it.
- One day's run on one machine, with each tool's public rules as of that day.

## Running Snyk Code

Snyk Code needs a Snyk account. If you have one, log in with the Snyk CLI
(`snyk auth`) and run `TOOLS="snyk" sh bench/sast-compare-2026-11/run.sh`; the
script calls `snyk code test --sarif` in each target and the scorer reads its
SARIF output. The script never reads, asks for or stores a token. We would
publish the result, including where phpwarden loses.

## Files

- `run.sh`: fetches the pinned targets and the tools into `$BENCH_DATA`, runs
  every tool on every target with timing, then scores.
- `score.py`: normalisation, category mapping, ground truth and tables;
  `score.py --sample WORKDIR` prints the clean-code samples to triage.
- `triage.json`: the hand verdict for every sampled clean-code finding.
- `results-2026-11-14.txt`: the scorer's output for the run reported here.
