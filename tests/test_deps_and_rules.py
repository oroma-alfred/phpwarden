#!/usr/bin/env python3
"""Validate Composer dependency scanning and WAF rule generation."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phpwarden import rules as rulegen  # noqa: E402
from phpwarden import version as V  # noqa: E402
from phpwarden.deps import constraint_matches, scan_lock  # noqa: E402
from phpwarden.feed import FeedManager  # noqa: E402
from phpwarden.vulndb import Feed  # noqa: E402

# Deterministic assertions run against the fixed curated base feed; the scale
# assertion at the end uses the full shipped feed.
feed = Feed.load(ROOT / "feedbuilder" / "base" / "php-cve-feed.base.json")
ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and cond

# --- constraint evaluator boundaries (Guzzle: <7.4.5 | <6.5.8) --------------
AFF = ">=7.0.0,<7.4.5|>=6.0.0,<6.5.8"
check("7.4.4 is affected", constraint_matches("7.4.4", AFF))
check("7.4.5 is NOT affected (fixed)", not constraint_matches("7.4.5", AFF))
check("6.5.7 is affected", constraint_matches("6.5.7", AFF))
check("6.5.8 is NOT affected (fixed)", not constraint_matches("6.5.8", AFF))
check("5.9.0 is NOT affected (below both ranges)", not constraint_matches("5.9.0", AFF))

# --- loose dotted versions: 2-segment and 4-segment (WordPress-style) -------
check("2-segment '6.3' < '6.4' matched by <6.4", constraint_matches("6.3", "<6.4"))
check("2-segment '6.4' NOT matched by <6.4", not constraint_matches("6.4", "<6.4"))
check("4-segment '6.3.0.1' matched by <=6.3.0.1", constraint_matches("6.3.0.1", "<=6.3.0.1"))
check("4-segment '6.3.0.2' NOT matched by <=6.3.0.1", not constraint_matches("6.3.0.2", "<=6.3.0.1"))

# --- composer.lock scan -----------------------------------------------------
lock = {
    "packages": [
        {"name": "phpmailer/phpmailer", "version": "5.2.15"},   # vuln (<5.2.20)
        {"name": "guzzlehttp/guzzle", "version": "7.4.0"},       # vuln (31090 + 31091)
        {"name": "facade/ignition", "version": "2.5.5"},         # safe (>=2.5.2)
        {"name": "symfony/console", "version": "6.0.0"},         # no advisory
    ],
    "packages-dev": [
        {"name": "phpunit/phpunit", "version": "10.0.0"},        # no advisory
    ],
}
tmp = Path(tempfile.mkdtemp()) / "composer.lock"
tmp.write_text(json.dumps(lock))
findings = scan_lock(tmp, feed)
ids = sorted((f.package, f.advisory.cve) for f in findings)
print("   findings:", ids)
check("phpmailer flagged (CVE-2016-10033)", ("phpmailer/phpmailer", "CVE-2016-10033") in ids)
check("guzzle flagged for both CVEs",
      ("guzzlehttp/guzzle", "CVE-2022-31090") in ids and ("guzzlehttp/guzzle", "CVE-2022-31091") in ids)
check("patched ignition NOT flagged", not any(f.package == "facade/ignition" for f in findings))
check("unaffected symfony/phpunit NOT flagged",
      not any(f.package in ("symfony/console", "phpunit/phpunit") for f in findings))
check("3 findings total", len(findings) == 3)
check("known-exploited surfaced for phpmailer",
      any(f.advisory.known_exploited for f in findings if f.package == "phpmailer/phpmailer"))

# --- WAF rule generation ----------------------------------------------------
ms = rulegen.generate(feed, "modsecurity")
ng = rulegen.generate(feed, "nginx")
check("modsecurity output has SecRule + a CVE tag", "SecRule" in ms and "CVE-2024-4577" in ms)
check("modsecurity rule ids are assigned", "id:9100000" in ms)
check("nginx output blocks with 403", "return 403" in ng and "CVE-2019-11043" in ng)

# --- scale: the full shipped feed catches long-tail imported packages -------
full = FeedManager().current()
check("full feed has 1000+ composer advisories (FriendsOfPHP scale)", len(full.composer) >= 1000)
lock2 = {"packages": [{"name": "adodb/adodb-php", "version": "5.20.0"}]}
tmp2 = Path(tempfile.mkdtemp()) / "composer.lock"
tmp2.write_text(json.dumps(lock2))
full_findings = scan_lock(tmp2, full)
check("full feed flags an imported package (adodb/adodb-php 5.20.0)", len(full_findings) >= 1)

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
