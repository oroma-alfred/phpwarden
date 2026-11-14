#!/usr/bin/env python3
"""WAF dry-run rules and the --replay report."""
import json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from phpwarden import rules  # noqa: E402
from phpwarden.vulndb import Feed  # noqa: E402

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and bool(cond)

feed = Feed.bundled()
sigs = rules._request_sigs(feed)
check("feed has request signatures to test with", len(sigs) > 0)
cve, pat, _ = sigs[0]

block, dry = rules.generate(feed, "modsecurity"), rules.generate(feed, "modsecurity", dry_run=True)
rl = lambda t: [l for l in t.splitlines() if l.startswith("SecRule")]
check("modsecurity: blocking rules deny with 403", all("deny,status:403" in l for l in rl(block)) and rl(block))
check("modsecurity dry-run: no rule denies", not any("deny" in l or "status:403" in l for l in rl(dry)))
check("modsecurity dry-run: every rule passes and logs", all("pass,log,auditlog" in l for l in rl(dry)))
check("modsecurity dry-run: same number of rules and same ids",
      len(rl(dry)) == len(rl(block)) and [l.split("id:")[1].split(",")[0] for l in rl(dry)]
      == [l.split("id:")[1].split(",")[0] for l in rl(block)])
check("modsecurity dry-run: messages are marked", all("DRY-RUN (would block)" in l for l in rl(dry)))

nb, nd = rules.generate(feed, "nginx"), rules.generate(feed, "nginx", dry_run=True)
ifs = lambda t: [l for l in t.splitlines() if l.startswith("if (")]
check("nginx: blocking rules return 403", all("return 403" in l for l in ifs(nb)) and ifs(nb))
check("nginx dry-run: nothing returns 403", "return 403" not in "\n".join(l for l in nd.splitlines() if not l.startswith("#")))
check("nginx dry-run: variable initialised once, set per rule",
      nd.count('set $phpwarden_would_block "";') == 1
      and all("set $phpwarden_would_block" in l for l in ifs(nd)) and len(ifs(nd)) == len(ifs(nb)))
check("default output is unchanged by the new flag", rules.generate(feed, "nginx", dry_run=False) == nb)

tmp = Path(tempfile.mkdtemp(prefix="pwwaf-"))
log = tmp / "access.log"
attack = f'/index.php?x={pat}'
log.write_text("\n".join([
    '203.0.113.7 - - [13/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    f'198.51.100.9 - - [13/Nov/2026:10:00:01 +0000] "GET {attack} HTTP/1.1" 404 10 "-" "curl/8"',
    f'198.51.100.9 - - [13/Nov/2026:10:00:02 +0000] "GET {attack} HTTP/1.1" 404 10 "-" "curl/8"',
    f'203.0.113.50 - - [13/Nov/2026:10:00:03 +0000] "GET {attack} HTTP/1.1" 200 900 "-" "Mozilla/5.0"',
    '203.0.113.7 - - [13/Nov/2026:10:00:04 +0000] "GET /about HTTP/1.1" 200 300 "-" "Mozilla/5.0"',
]) + "\n")
rep = rules.replay(feed, log)
row = next((c for c in rep["by_cve"] if c["cve"] == cve), None)
check("replay: counts lines and would-block requests", rep["scanned_lines"] == 5 and rep["would_block"] == 3)
check("replay: per-CVE count and the 2xx one flagged for review",
      row and row["requests"] == 3 and row["served_2xx_3xx"] == 1 and rep["review"] >= 1)
check("replay: top client is the prober", rep["top_clients"][0] == {"ip": "198.51.100.9", "requests": 2})
check("replay: path has no query string", rep["top_paths"][0]["path"] == "/index.php")

ENV = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PHPWARDEN_HOME=str(tmp / "home"), PHPWARDEN_FREE_FEED_URL="off")
def run(*a):
    p = subprocess.run([sys.executable, "-m", "phpwarden.cli", *a], capture_output=True, text=True, env=ENV)
    return p.returncode, p.stdout, p.stderr
rc, out, _ = run("rules", "--format", "nginx", "--dry-run")
check("cli: rules --dry-run prints log-only rules", rc == 0 and "DRY-RUN" in out and "return 403" not in out.split('set $phpwarden_would_block "";')[1])
rc, out, _ = run("rules", "--replay", str(log))
check("cli: --replay text report", rc == 0 and "3 request(s) would be blocked" in out and "false positives" in out)
rc, out, _ = run("rules", "--replay", str(log), "--json")
check("cli: --replay --json", rc == 0 and json.loads(out)["would_block"] == 3)
rc, out, err = run("rules", "--replay", str(tmp / "missing.log"))
check("cli: missing log is exit 4, not 'nothing would be blocked'", rc == 4 and "error" in err)
clean = tmp / "clean.log"; clean.write_text('203.0.113.7 - - [13/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"\n')
rc, out, _ = run("rules", "--replay", str(clean))
check("cli: clean log says nothing would change", rc == 0 and "0 request(s) would be blocked" in out)

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
