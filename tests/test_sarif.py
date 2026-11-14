#!/usr/bin/env python3
"""--format sarif on scan, deps and wordpress."""
import json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from phpwarden import sarif  # noqa: E402

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and bool(cond)

tmp = Path(tempfile.mkdtemp(prefix="pwsarif-"))
ENV = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PHPWARDEN_HOME=str(tmp / "home"),
           PHPWARDEN_FREE_FEED_URL="off")
ENV.pop("PHPWARDEN_LICENSE", None)

def run(*args):
    p = subprocess.run([sys.executable, "-m", "phpwarden.cli", *args], capture_output=True, text=True, env=ENV)
    return p.returncode, p.stdout, p.stderr

def shape(d):
    r = d["runs"][0]
    return (d["version"] == "2.1.0" and r["tool"]["driver"]["name"] == "phpwarden"
            and all({"ruleId", "level", "message", "locations"} <= set(x) for x in r["results"])
            and {x["ruleId"] for x in r["results"]} <= {x["id"] for x in r["tool"]["driver"]["rules"]})

check("level: KEV is error even when severity is low", sarif.level("low", True) == "error")
check("level: EPSS 60% is error", sarif.level("medium", False, 0.6) == "error")
check("level: medium -> warning, low -> note, high -> error",
      (sarif.level("medium"), sarif.level("low"), sarif.level("high")) == ("warning", "note", "error"))

lock = tmp / "composer.lock"
lock.write_text(json.dumps({"packages": [
    {"name": "symfony/polyfill", "version": "v1.0.0"},
    {"name": "phpmailer/phpmailer", "version": "v5.2.16"}], "packages-dev": []}, indent=4))
rc, out, err = run("deps", str(lock), "--format", "sarif", "--no-reachability")
d = json.loads(out)
res = d["runs"][0]["results"]
kev = [r for r in res if r["ruleId"] == "CVE-2016-10033"]
want_line = next(i for i, l in enumerate(lock.read_text().splitlines(), 1) if "phpmailer/phpmailer" in l)
check("deps sarif: valid shape, exit code still 1", shape(d) and rc == 1)
check("deps sarif: KEV finding is error with the KEV tag", kev and kev[0]["level"] == "error"
      and "[KEV" in kev[0]["message"]["text"] and kev[0]["properties"]["known_exploited"] is True)
check("deps sarif: points at the package's line in composer.lock",
      kev[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == want_line)
rule = next(r for r in d["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "CVE-2016-10033")
check("deps sarif: rule has security-severity and helpUri",
      rule["properties"].get("security-severity") == "9.8" and rule["helpUri"].endswith("/CVE-2016-10033"))
rc2, out2, _ = run("deps", str(lock), "--json", "--no-reachability")
check("same findings as --json", len(json.loads(out2)["vulnerable"]) == len(res))
rc3, out3, _ = run("deps", str(lock), "--format", "json", "--no-reachability")
check("--format json equals --json", out3 == out2)
clean = tmp / "clean.lock"; clean.write_text(json.dumps({"packages": [], "packages-dev": []}))
rc, out, _ = run("deps", str(clean), "--format", "sarif")
check("clean lockfile: empty results, exit 0", rc == 0 and json.loads(out)["runs"][0]["results"] == [])

wproot = tmp / "wp"; (wproot / "wp-includes").mkdir(parents=True)
(wproot / "wp-includes" / "version.php").write_text("<?php\n$wp_version = '6.4.2';\n")
pl = wproot / "wp-content" / "plugins" / "litespeed-cache"; pl.mkdir(parents=True)
(pl / "litespeed-cache.php").write_text("<?php\n/*\nPlugin Name: LiteSpeed Cache\nVersion: 6.2\n*/\n")
rc, out, _ = run("wordpress", str(wproot), "--format", "sarif")
d = json.loads(out)
uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in d["runs"][0]["results"]}
check("wordpress sarif: valid shape", shape(d) and rc == 1)
check("wordpress sarif: plugin and core locations",
      any(u.endswith("wp-content/plugins/litespeed-cache") for u in uris)
      and any(u.endswith("wp-includes/version.php") for u in uris))

rc, out, _ = run("scan", "--version", "8.1.0", "--sapi", "fpm", "--os", "linux", "--format", "sarif")
d = json.loads(out)
check("scan sarif: valid shape with findings", shape(d) and len(d["runs"][0]["results"]) > 0)
rc, out, err = run("deps", str(lock), "--format", "xml")
check("unknown format is a usage error (64)", rc == 64)

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
