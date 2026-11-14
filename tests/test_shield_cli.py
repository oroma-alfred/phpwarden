#!/usr/bin/env python3
"""phpwarden shield CLI: policy, install, report, promote."""
import json, os, subprocess, sys, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name); ok = ok and bool(cond)
tmp = Path(tempfile.mkdtemp(prefix="pwshield-"))
ENV = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PHPWARDEN_HOME=str(tmp / "home"), PHPWARDEN_FREE_FEED_URL="off")
def run(*a):
    p = subprocess.run([sys.executable, "-m", "phpwarden.cli", "shield", *a], capture_output=True, text=True, env=ENV)
    return p.returncode, p.stdout, p.stderr
site = tmp / "site"; site.mkdir()
(site / "composer.lock").write_text(json.dumps({"packages": [{"name": "phpunit/phpunit", "version": "5.6.2"}], "packages-dev": []}))
rc, out, _ = run("policy", str(site), "--out", str(tmp / "p.json"))
pol = json.loads((tmp / "p.json").read_text())
check("policy: written as JSON + .php twin, log mode", rc == 0 and (tmp / "p.php").exists() and pol["mode"] == "log")
check("policy: rule for the installed exploited package, scoped", any(r["id"] == "phpunit-eval-stdin" for r in pol["rules"]))
check("policy: no rule for things not installed", not any("ignition" in r["id"] for r in pol["rules"]))
(site / "composer.lock").write_text(json.dumps({"packages": [{"name": "phpunit/phpunit", "version": "9.6.0"}], "packages-dev": []}))
rc, out, _ = run("policy", str(site), "--out", str(tmp / "p2.json"))
check("policy: the rule is dropped once the package is upgraded",
      not any(r["id"] == "phpunit-eval-stdin" for r in json.loads((tmp / "p2.json").read_text())["rules"]))
rc, out, err = run("policy", str(tmp / "nope"))
check("policy: missing directory is exit 4", rc == 4)
rc, out, _ = run("install", "--dest", str(tmp / "agent"))
check("install: copies the agent and prints load instructions without changing anything else",
      rc == 0 and (tmp / "agent" / "phpwarden-shield.php").read_text().startswith("<?php") and "auto_prepend_file" in out)
rc, out, _ = run("promote", str(tmp / "p.json"), "--log", os.devnull)
check("promote without the explicit flag changes nothing",
      rc == 0 and "operator acknowledgement required" in out and json.loads((tmp / "p.json").read_text())["mode"] == "log")
rc, out, _ = run("promote", str(tmp / "p.json"), "--log", os.devnull, "--i-understand-this-blocks-requests")
check("promote before 7 days of logging is refused", "burn-in" in out and json.loads((tmp / "p.json").read_text())["mode"] == "log")
old = json.loads((tmp / "p.json").read_text()); old["created"] = int(time.time()) - 8 * 86400
(tmp / "p.json").write_text(json.dumps(old))
rc, out, _ = run("promote", str(tmp / "p.json"), "--log", os.devnull, "--i-understand-this-blocks-requests", "--rule", "phpunit-eval-stdin")
new = json.loads((tmp / "p.json").read_text())
check("promote after burn-in, one rule: only that rule blocks", "BLOCK  phpunit-eval-stdin" in out and new["mode"] == "enforce"
      and [r["id"] for r in new["rules"] if r["mode"] == "block"] == ["phpunit-eval-stdin"])
log = tmp / "shield.log"
log.write_text(json.dumps({"ts": int(time.time()), "rule": "phpunit-eval-stdin", "cve": "CVE-2017-9841", "action": "log",
                           "ip": "198.51.100.9", "path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"}) + "\n")
rc, out, _ = run("report", str(log))
check("report summarises hits", rc == 0 and "phpunit-eval-stdin" in out)
rc, out, err = run("report", str(tmp / "missing.log"))
check("report on a missing log is exit 4", rc == 4)
pkg = ROOT / "src" / "phpwarden" / "shield" / "agent" / "phpwarden-shield.php"
check("the packaged agent is identical to integrations/php-shield", pkg.read_bytes() == (ROOT / "integrations/php-shield/phpwarden-shield.php").read_bytes())
print("\nRESULT:", "ALL PASS" if ok else "FAILURES"); sys.exit(0 if ok else 1)
