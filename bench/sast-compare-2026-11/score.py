#!/usr/bin/env python3
"""Score the SAST comparison from the raw results in a work dir.

  score.py <workdir>               score everything run.sh produced
  score.py --psalm-config <root>   print the minimal psalm.xml run.sh uses
  score.py --sample <workdir>      print the clean-code samples to triage

Every tool's findings are normalised to (file, line, category, high?, trace
files) so the same ground truth applies to all of them:

* DVWA ships, per vulnerability type, deliberately vulnerable low/medium/high
  levels and a fixed `impossible` level. A finding of the matching category in
  `vulnerabilities/<type>/source/<level>.php`, or whose reported data-flow trace
  passes through that file, counts as found. The same on `impossible.php` is a
  wrong flag. (Traces matter: Psalm and phpwarden's AST engine often report the
  sink in index.php while the level file is where the input is read.)
* Mutillidae: 11 pages whose vulnerability the project documents.
* Clean code (WordPress, Laravel, Symfony): every high/critical finding is
  presumed noise until triaged; a seeded random sample per tool and target is
  hand-checked and the verdicts kept in triage.json.
"""
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATS = ["sqli", "cmdi", "code", "include", "path", "xss", "ssrf", "deser", "redirect", "xxe", "upload"]
CAT_NAME = {"sqli": "SQL injection", "cmdi": "command injection", "code": "code execution",
            "include": "file inclusion", "path": "path traversal / file access", "xss": "XSS",
            "ssrf": "SSRF", "deser": "deserialization", "redirect": "open redirect", "xxe": "XXE",
            "upload": "unrestricted upload"}

# ---------------------------------------------------------------- ground truth
DVWA = {"sqli": {"sqli"}, "sqli_blind": {"sqli"}, "exec": {"cmdi"}, "fi": {"include", "path"},
        "xss_r": {"xss"}, "xss_s": {"xss"}, "upload": {"upload", "path"}, "open_redirect": {"redirect"}}
LEVELS = ["low", "medium", "high"]
MUTILLIDAE = [
    ("user-info.php", "SQL injection", {"sqli"}),
    ("includes/process-login-attempt.php", "SQL injection (login)", {"sqli"}),
    ("add-to-your-blog.php", "SQL injection / stored XSS", {"sqli", "xss"}),
    ("dns-lookup.php", "command injection", {"cmdi"}),
    ("echo.php", "command injection", {"cmdi"}),
    ("index.php", "local file inclusion", {"include"}),
    ("source-viewer.php", "arbitrary file read", {"path", "include"}),
    ("text-file-viewer.php", "remote file read / SSRF", {"path", "ssrf"}),
    ("xml-validator.php", "XML external entity", {"xxe"}),
    ("upload-file.php", "unrestricted upload", {"upload", "path"}),
    ("redirectandlog.php", "open redirect", {"redirect", "xss"}),
]
CLEAN = ["wordpress", "laravel", "symfony"]
TOOLS = ["phpwarden-tokens", "phpwarden-auto", "semgrep", "psalm", "snyk"]

# ------------------------------------------------------- per-tool category maps
# phpwarden: from the rule's category in its own rule table, plus a few ids.
PW_CATEGORY = {"sql-injection": "sqli", "command-injection": "cmdi", "code-execution": "code",
               "file-inclusion": "include", "path-traversal": "path", "xss": "xss", "ssrf": "ssrf",
               "deserialization": "deser", "open-redirect": "redirect", "xxe": "xxe"}
PW_RULE = {"path-move-upload": "upload", "upload-unrestricted": "upload", "blade-raw": "xss", "twig-raw": "xss",
           "xss-response": "xss", "ssrf-http-client": "ssrf", "cmd-process": "cmdi",
           "second-order-injection": "sqli"}
# Semgrep: by CWE in the rule metadata, else by words in the rule id.
CWE_CAT = {"89": "sqli", "78": "cmdi", "77": "cmdi", "94": "code", "95": "code", "98": "include",
           "22": "path", "73": "path", "23": "path", "79": "xss", "918": "ssrf", "502": "deser",
           "601": "redirect", "611": "xxe", "434": "upload"}
SG_WORDS = [("sql", "sqli"), ("exec", "cmdi"), ("shell", "cmdi"), ("command", "cmdi"), ("eval", "code"),
            ("include", "include"), ("filename", "path"), ("file", "path"), ("echo", "xss"), ("xss", "xss"),
            ("ssrf", "ssrf"), ("unserialize", "deser"), ("redirect", "redirect"), ("xxe", "xxe"),
            ("upload", "upload")]
# Semgrep rules whose one CWE label undersells what they match: tainted-filename
# fires on request data reaching any file-opening function, which covers file
# inclusion and file access as well as SSRF, so it counts for all three.
SG_RULE = {"tainted-filename": {"path", "include", "ssrf"}, "tainted-exec": {"cmdi"},
           "run-shell-injection": {"cmdi"}}
# Psalm: by issue type.
PSALM_TYPE = {"TaintedSql": "sqli", "TaintedShell": "cmdi", "TaintedEval": "code", "TaintedCallable": "code",
              "TaintedInclude": "include", "TaintedFile": "path", "TaintedHtml": "xss",
              "TaintedTextWithQuotes": "xss", "TaintedSSRF": "ssrf", "TaintedUnserialize": "deser",
              "TaintedHeader": "redirect", "TaintedXpath": "xxe"}


def _rel(p, root):
    p = str(p).replace("\\", "/")
    root = str(root).replace("\\", "/").rstrip("/") + "/"
    return p[len(root):] if p.startswith(root) else p.lstrip("./")


def _pw_rules():
    sys.path.insert(0, str(HERE.parent.parent / "src"))
    from phpwarden import code_rules
    return {r["id"]: r for r in code_rules.RULES}


def normalise(tool, doc, root):
    """-> list of {file, line, cat, high, rule, trace}; [] when the tool failed."""
    out = []
    if tool.startswith("phpwarden"):
        rules = _pw_rules()
        for f in doc.get("findings", []):
            r = rules.get(f["rule"], {})
            cat = PW_RULE.get(f["rule"]) or PW_CATEGORY.get(r.get("category", ""))
            trace = [_rel(h.get("file", ""), root) for h in (f.get("trace") or []) if isinstance(h, dict)]
            out.append({"file": _rel(f["file"], root), "line": f.get("line", 0), "cat": cat, "cats": {cat} - {None},
                        "high": f.get("severity") in ("critical", "high"), "rule": f["rule"], "trace": trace})
    elif tool == "semgrep":
        for r in doc.get("results", []):
            md = (r.get("extra") or {}).get("metadata") or {}
            cwes = " ".join(md.get("cwe", []) if isinstance(md.get("cwe"), list) else [str(md.get("cwe", ""))])
            cat = next((c for n, c in CWE_CAT.items() if f"CWE-{n}:" in cwes or cwes.endswith(f"CWE-{n}")), None)
            if cat is None:
                cid = r["check_id"].lower()
                cat = next((c for w, c in SG_WORDS if w in cid.split(".")[-1]), None)
            if not r["path"].endswith((".php", ".phtml", ".inc", ".module")):
                continue          # the owasp pack also has YAML/JS rules; this is a PHP benchmark
            short = r["check_id"].split(".")[-1]
            cats = SG_RULE.get(short) or ({cat} - {None})
            out.append({"file": _rel(r["path"], root), "line": r["start"]["line"], "cat": cat or next(iter(cats), None), "cats": cats,
                        "high": (r.get("extra") or {}).get("severity") == "ERROR",
                        "rule": r["check_id"].split(".")[-1], "trace": []})
    elif tool == "psalm":
        # SARIF report: it carries Psalm's taint traces (codeFlows); the JSON report does not.
        for run in (doc.get("runs", []) if isinstance(doc, dict) else []):
            names = {r["id"]: r.get("name", r["id"]) for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for r in run.get("results", []):
                t = names.get(r.get("ruleId"), r.get("ruleId", ""))
                if not str(t).startswith("Tainted"):
                    continue
                loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
                trace = []
                for cf in r.get("codeFlows") or []:
                    for tf in cf.get("threadFlows") or []:
                        trace += [_rel(l["location"]["physicalLocation"]["artifactLocation"]["uri"], root)
                                  for l in tf.get("locations", []) if "location" in l]
                cat = PSALM_TYPE.get(t)
                out.append({"file": _rel(loc.get("artifactLocation", {}).get("uri", ""), root),
                            "line": loc.get("region", {}).get("startLine", 0), "cat": cat, "cats": {cat} - {None},
                            "high": True, "rule": t, "trace": trace})
    elif tool == "snyk":
        for run in doc.get("runs", []) if isinstance(doc, dict) else []:
            for r in run.get("results", []):
                loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
                rid = r.get("ruleId", "").lower()
                cat = next((c for w, c in SG_WORDS if w in rid), None)
                out.append({"file": _rel(loc.get("artifactLocation", {}).get("uri", ""), root),
                            "line": loc.get("region", {}).get("startLine", 0), "cat": cat, "cats": {cat} - {None},
                            "high": r.get("level") == "error", "rule": r.get("ruleId", ""), "trace": []})
    return out


def _touches(f, path):
    return f["file"] == path or path in f["trace"]


def loc(root):
    n = 0
    for p in Path(root).rglob("*.php"):
        if set(p.parts) & {"vendor", "node_modules", ".git", "tests", "Tests", "test"} or p.name.endswith("Test.php"):
            continue
        try:
            n += sum(1 for _ in open(p, "rb"))
        except OSError:
            pass
    return n


def psalm_config(root):
    root = Path(root)
    # The same exclusions every tool gets: dependencies and test suites, at any depth
    # (the Symfony monorepo keeps a Tests/ folder inside every component).
    skip = {"vendor", "tests", "Tests", "test", "node_modules"}
    dirs = []
    for p in sorted(root.rglob("*")):
        if p.is_dir() and p.name in skip and not (set(p.relative_to(root).parts[:-1]) & skip):
            dirs.append(str(p.relative_to(root)))
    ignore = "".join(f'<directory name="{d}"/>' for d in dirs)
    return ('<?xml version="1.0"?>\n<psalm errorLevel="8" resolveFromConfigFile="true" findUnusedCode="false" '
            'findUnusedBaselineEntry="false">\n  <projectFiles><directory name="."/>'
            + (f"<ignoreFiles>{ignore}</ignoreFiles>" if ignore else "") + "</projectFiles>\n</psalm>\n")


def load_all(w):
    w = Path(w)
    timing, results, failed = {}, {}, {}
    tpath = w / "out" / "timing.txt"
    for ln in (tpath.read_text().splitlines() if tpath.exists() else []):
        p = ln.split()
        if len(p) >= 5:
            timing[(p[0], p[1])] = (float(p[3]) - float(p[2]), int(p[4]))
    for tool in TOOLS:
        for t in ["dvwa", "mutillidae"] + CLEAN:
            f = w / "out" / f"{tool}-{t}.{'sarif' if tool in ('psalm', 'snyk') else 'json'}"
            if not f.exists():
                continue
            try:
                doc = json.loads(f.read_text() or "null")
            except ValueError as e:
                failed[(tool, t)] = f"unreadable output: {e}"
                continue
            if doc is None:
                failed[(tool, t)] = "empty output"
                continue
            results[(tool, t)] = normalise(tool, doc, w / "targets" / t)
    return timing, results, failed


def sample(results, tool, t, k=15):
    hs = sorted((f for f in results.get((tool, t), []) if f["high"]), key=lambda f: (f["file"], f["line"], f["rule"]))
    rnd = random.Random(f"{tool}|{t}|2026-11-14")
    return hs if len(hs) <= k else sorted(rnd.sample(hs, k), key=lambda f: (f["file"], f["line"]))


def main(w):
    w = Path(w)
    timing, results, failed = load_all(w)
    tools = [x for x in TOOLS if any(k[0] == x for k in results)]
    print("tools:", ", ".join(tools))
    for k, v in sorted(failed.items()):
        print(f"FAILED {k[0]} on {k[1]}: {v}")

    print("\n== 1. DVWA: found per vulnerability type and level (low / medium / high), wrong flags on impossible ==")
    hdr = f"{'type':<14}" + "".join(f"{x:>20}" for x in tools)
    print(hdr)
    tot = {x: Counter() for x in tools}
    for vt, cats in DVWA.items():
        row = f"{vt:<14}"
        for x in tools:
            fs = results.get((x, "dvwa"), [])
            cells = []
            for lv in LEVELS + ["impossible"]:
                path = f"vulnerabilities/{vt}/source/{lv}.php"
                hit = any(f["cats"] & cats and _touches(f, path) for f in fs)
                cells.append(hit)
                tot[x][lv] += hit
            row += f"{''.join('x' if c else '.' for c in cells[:3]) + ('  WRONG' if cells[3] else ''):>20}"
        print(row)
    print(f"{'found (of 8)':<14}" + "".join(f"{tot[x]['low']:>8}/{tot[x]['medium']}/{tot[x]['high']:<9}" for x in tools))
    print(f"{'wrong flags':<14}" + "".join(f"{tot[x]['impossible']:>20}" for x in tools))

    print("\n== 2. Mutillidae: 11 documented vulnerable pages ==")
    print(f"{'page':<40}" + "".join(f"{x:>18}" for x in tools))
    mt = Counter()
    for page, what, cats in MUTILLIDAE:
        row = f"{page[:39]:<40}"
        for x in tools:
            fs = results.get((x, "mutillidae"), [])
            hit = any(f["cats"] & cats and (_touches(f, "src/" + page) or _touches(f, page)) for f in fs)
            mt[x] += hit
            row += f"{'found' if hit else '-':>18}"
        print(row)
    print(f"{'found (of 11)':<40}" + "".join(f"{mt[x]:>18}" for x in tools))

    print("\n== 3. Clean code: high/critical findings (presumed noise), per 100k lines ==")
    triage = json.loads((HERE / "triage.json").read_text()) if (HERE / "triage.json").exists() else {}
    print(f"{'target':<11}{'lines':>9}" + "".join(f"{x:>22}" for x in tools))
    for t in CLEAN:
        n = loc(w / "targets" / t) if (w / "targets" / t).exists() else 0
        row = f"{t:<11}{n:>9}"
        for x in tools:
            if (x, t) not in results:
                row += f"{'not run' if (x, t) not in failed else 'FAILED':>22}"
                continue
            hs = [f for f in results[(x, t)] if f["high"]]
            row += f"{len(hs):>9} ({(len(hs) * 100000 / n if n else 0):5.1f}/100k)  "
        print(row)
    print("\n   triaged samples (true positive / false positive / by design):")
    for t in CLEAN:
        for x in tools:
            s = sample(results, x, t)
            if not s:
                continue
            v = Counter(triage.get(f"{x}|{t}|{f['file']}:{f['line']}|{f['rule']}", {}).get("verdict", "untriaged")
                        for f in s)
            print(f"   {t:<10} {x:<17} sampled {len(s):>2}: " + ", ".join(f"{k} {n}" for k, n in v.most_common()))

    print("\n== 4. Runtime (wall seconds, exit code) ==")
    print(f"{'target':<11}" + "".join(f"{x:>18}" for x in tools))
    for t in ["dvwa", "mutillidae"] + CLEAN:
        print(f"{t:<11}" + "".join(
            f"{(f'{timing[(x, t)][0]:.1f}s rc{timing[(x, t)][1]}' if (x, t) in timing else '-'):>18}" for x in tools))

    print("\n== 5. Findings by category (all severities) ==")
    for t in ["dvwa", "mutillidae"] + CLEAN:
        print(f"  {t}: " + "; ".join(
            f"{x} " + ",".join(f"{c}={n}" for c, n in sorted(Counter(f['cat'] or 'other' for f in results.get((x, t), [])).items()))
            for x in tools if (x, t) in results))


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--psalm-config":
        sys.stdout.write(psalm_config(sys.argv[2]))
    elif len(sys.argv) >= 3 and sys.argv[1] == "--sample":
        _, res, _ = load_all(sys.argv[2])
        for t in CLEAN:
            for x in TOOLS:
                for f in sample(res, x, t):
                    print(json.dumps({"key": f"{x}|{t}|{f['file']}:{f['line']}|{f['rule']}", "cat": f["cat"]}))
    else:
        main(sys.argv[1])
