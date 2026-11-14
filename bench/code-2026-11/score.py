#!/usr/bin/env python3
"""Score the code-scanner benchmark from the JSON results in a work dir.

  score.py <workdir>     (run.sh calls this)

DVWA ships, for each vulnerability type, a deliberately vulnerable `low.php`
and a fixed `impossible.php`. That gives an objective check: a relevant finding
in low.php is a true positive, a relevant finding in impossible.php is a false
positive. "Relevant" = the rule category that matches the vulnerability type
(table below); findings of other categories are listed separately, not counted.
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# DVWA vulnerability dir -> rule-id prefixes that count as "found it"
DVWA = {
    "sqli": ("sql-",), "sqli_blind": ("sql-",),
    "exec": ("cmd-",),
    "fi": ("include-",),
    "xss_r": ("xss-",), "xss_s": ("xss-",),
    "upload": ("path-move-upload", "upload-unrestricted"),
    "open_redirect": ("redirect-",),
    # not in scope: logic, browser-side or configuration classes
    "xss_d": (), "csrf": (), "brute": (), "captcha": (), "weak_id": (), "csp": (),
    "javascript": (), "authbypass": (), "bac": (), "api": (), "cryptography": (),
}
# What `phpwarden code` is built to find: server-side injection classes where
# request data reaches a dangerous function. The other DVWA types are logic,
# browser-side or configuration problems that a scanner of this kind does not
# attempt (they are still printed, with whatever rules fired, for completeness).
IN_SCOPE = ["sqli", "sqli_blind", "exec", "fi", "xss_r", "xss_s", "upload", "open_redirect"]


# Mutillidae II pages whose vulnerability the project itself documents (its
# hints pages and OWASP write-ups): (file under src/, class, rule prefixes).
MUTILLIDAE = [
    ("user-info.php", "SQL injection", ("sql-",)),
    ("includes/process-login-attempt.php", "SQL injection (login)", ("sql-",)),
    ("add-to-your-blog.php", "SQL injection / stored XSS", ("sql-", "xss-")),
    ("dns-lookup.php", "command injection", ("cmd-",)),
    ("echo.php", "command injection", ("cmd-",)),
    ("index.php", "local file inclusion", ("include-",)),
    ("source-viewer.php", "arbitrary file read", ("path-",)),
    ("text-file-viewer.php", "remote file read / SSRF", ("path-", "ssrf-")),
    ("xml-validator.php", "XML external entity", ("xxe-",)),
    ("upload-file.php", "unrestricted upload", ("path-move-upload", "upload-unrestricted")),
    ("redirectandlog.php", "open redirect", ("redirect-", "xss-")),
]


def load(w, name):
    return json.loads((Path(w) / f"{name}.json").read_text())


def loc(root):
    n = files = 0
    for p in Path(root).rglob("*.php"):
        parts = set(p.parts)
        if parts & {"vendor", "node_modules", ".git", "tests", "Tests", "test"} or p.name.endswith("Test.php"):
            continue
        try:
            n += sum(1 for _ in open(p, "rb"))
            files += 1
        except OSError:
            pass
    return n, files


def main(w):
    w = Path(w)
    timing = {}
    for ln in (w / "timing.txt").read_text().split("\n"):
        if ln.strip():
            t, s, e, sha = ln.split()
            timing[t] = (float(e) - float(s), sha)

    print("== 1. DVWA: vulnerable low.php vs fixed impossible.php ==")
    d = load(w, "dvwa")
    by_file = defaultdict(list)
    for f in d["findings"]:
        by_file[f["file"]].append(f)
    tp = fp = total = 0
    print(f"{'type':<28}| {'low.php (vulnerable)':<52}| impossible.php (fixed)")
    for typ in sorted(DVWA):
        row = []
        for level in ("low", "impossible"):
            path = f"vulnerabilities/{typ}/source/{level}.php"
            if not (w / "dvwa" / path).exists():
                row.append("(no file)")
                continue
            rel = sorted({f["rule"] for f in by_file.get(path, []) if DVWA[typ] and f["rule"].startswith(DVWA[typ])})
            other = sorted({f["rule"] for f in by_file.get(path, [])} - set(rel))
            row.append((", ".join(rel) or "-") + (f"  [other: {', '.join(other)}]" if other else ""))
            if typ in IN_SCOPE:
                if level == "low":
                    total += 1
                    tp += bool(rel)
                else:
                    fp += bool(rel)
        scope = "" if typ in IN_SCOPE else " (out of scope)"
        print(f"{typ + scope:<28}| {row[0]:<52}| {row[1]}")
    print(f"\nIn-scope types: {tp}/{total} vulnerable files flagged with a relevant rule; "
          f"{fp}/{total} fixed files wrongly flagged with a relevant rule.")
    for level in ("medium", "high"):
        hit = sum(1 for typ in IN_SCOPE
                  if any(DVWA[typ] and f["rule"].startswith(DVWA[typ]) for f in by_file.get(f"vulnerabilities/{typ}/source/{level}.php", [])))
        n = sum(1 for typ in IN_SCOPE if (w / "dvwa" / f"vulnerabilities/{typ}/source/{level}.php").exists())
        print(f"  {level}.php (still vulnerable, with a partial filter): {hit}/{n} flagged")

    print("\n== 2. Mutillidae II: eleven well-known vulnerable pages ==")
    m = load(w, "mutillidae")
    mfile = defaultdict(set)
    for f in m["findings"]:
        mfile[f["file"]].add(f["rule"])
    hit = 0
    for page, what, prefixes in MUTILLIDAE:
        rules = sorted(r for r in mfile.get(f"src/{page}", ()) if r.startswith(prefixes))
        other = sorted(mfile.get(f"src/{page}", set()) - set(rules))
        hit += bool(rules)
        print(f"  {page:<38}{what:<28}{', '.join(rules) or 'MISSED'}" + (f"  [other: {', '.join(other)}]" if other else ""))
    print(f"\n{hit}/{len(MUTILLIDAE)} pages flagged with a relevant rule.")
    print("\nAll Mutillidae findings by rule:")
    print(f"files {m['files_scanned']}, summary {m['summary']}")
    for r, n in Counter(f["rule"] for f in m["findings"]).most_common():
        print(f"  {n:>3}  {r}")

    print("\n== 3. Clean codebases: findings per 100k lines ==")
    print(f"{'target':<11}{'files':>7}{'lines':>9}{'crit':>6}{'high':>6}{'med':>6}{'low':>6}{'high+crit /100k':>17}{'all /100k':>11}")
    for t in ("wordpress", "laravel", "symfony"):
        r = load(w, t)
        lines, _ = loc(w / t)
        s = r["summary"]
        hc = s.get("critical", 0) + s.get("high", 0)
        allf = sum(s.values())
        print(f"{t:<11}{r['files_scanned']:>7}{lines:>9}{s.get('critical',0):>6}{s.get('high',0):>6}"
              f"{s.get('medium',0):>6}{s.get('low',0):>6}{hc / lines * 1e5:>17.2f}{allf / lines * 1e5:>11.2f}")
    for t in ("wordpress", "laravel", "symfony"):
        r = load(w, t)
        print(f"\n{t}: by rule")
        for (rule, sev), n in sorted(Counter((f["rule"], f["severity"]) for f in r["findings"]).items(),
                                     key=lambda x: -x[1]):
            print(f"  {n:>3}  {sev:<8} {rule}")
        hc = [f for f in r["findings"] if f["severity"] in ("critical", "high")]
        if hc:
            print(f"  high/critical findings ({len(hc)}), for triage:")
            for f in hc:
                print(f"    {f['file']}:{f['line']}  {f['rule']}  | {f['snippet'][:110]}")

    print("\n== 4. Speed ==")
    for t in ("dvwa", "mutillidae", "wordpress", "laravel", "symfony"):
        r = load(w, t)
        secs, sha = timing[t]
        print(f"  {t:<11}{r['files_scanned']:>6} files  {secs:>6.2f} s  {r['files_scanned'] / secs:>7.0f} files/s  @ {sha[:12]}")


if __name__ == "__main__":
    main(sys.argv[1])
