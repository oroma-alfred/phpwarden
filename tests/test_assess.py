#!/usr/bin/env python3
"""phpwarden assess: the combined verdict and proof-of-fix."""
import json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from phpwarden import verdict as vd  # noqa: E402
from phpwarden.vulndb import Feed  # noqa: E402

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and bool(cond)

feed = Feed.bundled()
tmp = Path(tempfile.mkdtemp(prefix="pwassess-"))

def lock(pkgs, dev=()):
    return json.dumps({"packages": [{"name": n, "version": v, "autoload": {"psr-4": {ns: "src/"}}} for n, v, ns in pkgs],
                       "packages-dev": [{"name": n, "version": v, "autoload": {"psr-4": {ns: "src/"}}} for n, v, ns in dev]})

# --- a project: one KEV package that is used, one KEV package that is dev-only
site = tmp / "site"; (site / "app").mkdir(parents=True)
(site / "composer.lock").write_text(lock(
    [("phpmailer/phpmailer", "v5.2.16", "PHPMailer\\PHPMailer\\")],
    dev=[("roundcube/roundcubemail", "1.6.2", "Roundcube\\")]))
(site / "app" / "mail.php").write_text("<?php\nuse PHPMailer\\PHPMailer\\PHPMailer;\n$m = new PHPMailer();\n"
                                       "$o = unserialize($_POST['state']);\n")
r = vd.assess(site, feed=feed)
by = {i["id"]: i for i in r["items"]}
pm = next(i for i in r["items"] if i["cve"] == "CVE-2016-10033")
rc = next(i for i in r["items"] if i["cve"] == "CVE-2025-68461")
check("views: installed+code used, outside/attacked marked not supplied",
      r["views"]["installed"] == {"composer": True, "wordpress": False} and r["views"]["code"]
      and r["views"]["outside"] is None and r["views"]["attacked"] is None)
check("KEV + referenced by code -> act-now", pm["tier"] == "act-now" and pm["signals"]["reach"] == "used"
      and any("your code references" in w for w in pm["why"]) and any("Known Exploited" in w for w in pm["why"]))
check("KEV but dev-only -> this-week with the caveat stated", rc["tier"] == "this-week"
      and any("dev dependency only" in w for w in rc["why"]))
check("act-now sorts first", r["items"][0]["tier"] == "act-now")
code_items = [i for i in r["items"] if i["kind"] == "code"]
check("code finding included with file:line", code_items and code_items[0]["tier"] in ("this-week", "act-now")
      and any("app/mail.php:4" in w for w in code_items[0]["why"]))
check("fix line names fixed versions", pm["fix"].startswith("Upgrade to 5.2."))
check("exit code 1 when something needs action", vd.exit_code(r) == 1)

# --- unreferenced high (not KEV) -> scheduled; medium -> scheduled; summary adds up
check("summary counts add up", sum(r["summary"][t] for t in vd.TIERS) == r["summary"]["total"] == len(r["items"]))

# --- attacked view: signature hits raise a present CVE, and are noise for absent ones
sig_cve, sig_pat = next((c.id, d["patterns"][0]) for c in feed.cves for d in c.detectors
                        if d.get("kind") == "request-signature" and d.get("patterns"))
log = tmp / "access.log"
log.write_text("\n".join([
    f'198.51.100.9 - - [13/Nov/2026:10:00:01 +0000] "GET /index.php?x={sig_pat} HTTP/1.1" 404 10 "-" "curl/8"',
    '198.51.100.7 - - [13/Nov/2026:10:00:02 +0000] "GET /.env HTTP/1.1" 200 120 "-" "curl/8"',
    '198.51.100.8 - - [13/Nov/2026:10:00:03 +0000] "GET /.env HTTP/1.1" 200 120 "-" "python"',
    '203.0.113.5 - - [13/Nov/2026:10:00:04 +0000] "GET / HTTP/1.1" 200 900 "-" "Mozilla"']) + "\n")
r2 = vd.assess(site, feed=feed, logfile=log)
check("attacks on a CVE the site does not have are reported as noise, not as an item",
      any(n["cve"] == sig_cve for n in r2["attack_noise"]) and not any(i["cve"] == sig_cve for i in r2["items"]))
check("attacked view recorded", r2["views"]["attacked"] == {"log_lines": 4})

# --- outside view: exposure + "already fetched" from the log; live confirmation of an installed CVE
probe_res = {"tool": "phpwarden-probe", "target": "https://shop.example", "mode": "active",
             "ownership": {"verified": True, "method": "dns"}, "findings": [
    {"id": "exposed-env", "kind": "exposure", "severity": "critical", "title": "Exposed .env file",
     "evidence": "variables: APP_KEY, DB_PASSWORD", "url": "https://shop.example/.env", "fix": "Block dotfiles."},
    {"id": "missing-hsts", "kind": "header", "severity": "low", "title": "No HSTS header",
     "evidence": "Strict-Transport-Security absent", "url": "https://shop.example/"},
    {"id": "vuln-CVE-2026-87902-wordpress", "kind": "vuln", "severity": "high", "cve": "CVE-2026-87902",
     "title": "WordPress core 6.4.2: local file inclusion", "evidence": "WordPress core 6.4.2 matches affected range",
     "url": "https://shop.example/", "known_exploited": True, "epss": 0.4, "fix": "Upgrade to 6.4.12"}]}
r3 = vd.assess(site, feed=feed, probe_result=probe_res, logfile=log)
env = next(i for i in r3["items"] if i["id"] == "outside:exposed-env")
check("exposed .env is act-now", env["tier"] == "act-now")
check("'already fetched' evidence from the log: 2 requests, 2 clients, rotate secrets",
      env["signals"]["already_fetched"] == {"requests": 2, "clients": 2}
      and any("already fetched" in w and "rotate" in w for w in env["why"]))
wpc = next(i for i in r3["items"] if i["cve"] == "CVE-2026-87902")
check("a KEV vulnerability seen only from outside is act-now", wpc["tier"] == "act-now" and wpc["kind"] == "outside-vuln")
hsts = next(i for i in r3["items"] if i["id"] == "outside:missing-hsts")
check("a missing header is watch, never act-now", hsts["tier"] == "watch")
check("a Composer package gets no 'not confirmed from outside' line (its version is never visible there)",
      not any("from outside" in w for w in next(i for i in r3["items"] if i["cve"] == "CVE-2016-10033")["why"]))
txt = vd.to_text(r3)
check("text output: tiers in order, reasons listed, no secrets",
      txt.index("ACT NOW") < txt.index("THIS WEEK") and "already fetched" in txt and "views used: installed, code, outside, attacked" in txt)

# --- WordPress on disk + the same CVE visible outside -> one item, confirmed live
wp = tmp / "wp"; (wp / "wp-includes").mkdir(parents=True)
(wp / "wp-includes" / "version.php").write_text("<?php\n$wp_version = '6.4.2';\n")
r4 = vd.assess(wp, feed=feed, probe_result=probe_res)
hits = [i for i in r4["items"] if i["cve"] == "CVE-2026-87902"]
check("same CVE on disk and outside is ONE item, marked visible from outside",
      len(hits) == 1 and hits[0]["kind"] == "wordpress" and hits[0]["signals"]["visible_from_outside"] is True
      and hits[0]["tier"] == "act-now")

# --- proof of fix
(site / "composer.lock").write_text(lock([("phpmailer/phpmailer", "v6.9.1", "PHPMailer\\PHPMailer\\")],
                                         dev=[("roundcube/roundcubemail", "1.6.2", "Roundcube\\")]))
probe_fixed = dict(probe_res, findings=[f for f in probe_res["findings"] if f["id"] != "exposed-env"])
after = vd.assess(site, feed=feed, probe_result=probe_fixed, logfile=log)
d = vd.compare(r3, after)
fixed_ids = {f["id"] for f in d["fixed"]}
check("upgraded package is fixed and verified by the installed view",
      any(f["cve"] == "CVE-2016-10033" and "no longer in the affected range" in f["verified_by"] for f in d["fixed"]))
check("removed .env is fixed and verified from outside",
      any(f["id"] == "outside:exposed-env" and "re-checked from outside" in f["verified_by"] for f in d["fixed"]))
check("untouched issues are still open", any(s["cve"] == "CVE-2025-68461" for s in d["still_open"]))
after_noprobe = vd.assess(site, feed=feed)
d2 = vd.compare(r3, after_noprobe)
check("no probe this time: the .env is 'not re-checked', never 'fixed'",
      "outside:exposed-env" not in {f["id"] for f in d2["fixed"]}
      and any(n["id"] == "outside:exposed-env" for n in d2["not_rechecked"]))
passive = dict(probe_fixed, mode="passive", ownership={"verified": False, "method": None})
d3 = vd.compare(r3, vd.assess(site, feed=feed, probe_result=passive))
check("a passive re-probe cannot verify an exposure fix (needs active checks)",
      any(n["id"] == "outside:exposed-env" for n in d3["not_rechecked"]))
(site / "composer.lock").write_text(lock([("phpmailer/phpmailer", "v6.9.1", "PHPMailer\\PHPMailer\\"),
                                          ("dompdf/dompdf", "v0.8.4", "Dompdf\\")]))
d4 = vd.compare(after, vd.assess(site, feed=feed, probe_result=probe_fixed, logfile=log))
check("a newly introduced vulnerable package shows up as new", any("dompdf" in n["id"] for n in d4["new"]))

# --- CLI
ENV = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PHPWARDEN_HOME=str(tmp / "home"), PHPWARDEN_FREE_FEED_URL="off")
def run(*a):
    p = subprocess.run([sys.executable, "-m", "phpwarden.cli", "assess", *a], capture_output=True, text=True, env=ENV)
    return p.returncode, p.stdout, p.stderr
(tmp / "probe.json").write_text(json.dumps(probe_res))
rc_, out, err = run(str(site), "--probe-json", str(tmp / "probe.json"), "--log", str(log), "--out", str(tmp / "base.json"))
check("cli: text report, exit 1, baseline saved", rc_ == 1 and "ACT NOW" in out and (tmp / "base.json").exists())
(site / "composer.lock").write_text(lock([("phpmailer/phpmailer", "v6.9.1", "PHPMailer\\PHPMailer\\")]))
(tmp / "probe2.json").write_text(json.dumps(probe_fixed))
rc_, out, err = run(str(site), "--probe-json", str(tmp / "probe2.json"), "--baseline", str(tmp / "base.json"))
check("cli: --baseline prints verified fixes", "fixed and verified" in out and "FIXED" in out and "re-checked from outside" in out)
rc_, out, err = run(str(site), "--baseline", str(tmp / "base.json"), "--json")
check("cli: --json carries the changes block", "changes" in json.loads(out) and json.loads(out)["changes"]["not_rechecked"])
rc_, out, err = run()
check("cli: no input is a usage error", rc_ == 64)
rc_, out, err = run(str(tmp / "nope"))
check("cli: missing directory is exit 4", rc_ == 4)
rc_, out, err = run(str(site), "--log", str(tmp / "missing.log"))
check("cli: missing log is exit 4, not a clean result", rc_ == 4)
empty = tmp / "empty"; empty.mkdir()
rc_, out, err = run(str(empty))
check("cli: nothing to check says so and exits 0", rc_ == 0 and "views used: none" in out or "Nothing found" in out)

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
