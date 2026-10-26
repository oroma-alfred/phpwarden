#!/usr/bin/env python3
"""Validate WordPress exposure scanning and the fleet HTML report."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phpwarden import report as reportgen  # noqa: E402
from phpwarden import wordpress as wp  # noqa: E402
from phpwarden.feed import FeedManager  # noqa: E402
from phpwarden.vulndb import Feed  # noqa: E402

# Deterministic counts against the curated base; scale check uses the full feed.
feed = Feed.load(ROOT / "feedbuilder" / "base" / "php-cve-feed.base.json")
ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and cond

# --- build a fake WordPress install -----------------------------------------
wproot = Path(tempfile.mkdtemp(prefix="wp-")) / "wp"
(wproot / "wp-includes").mkdir(parents=True)
(wproot / "wp-includes" / "version.php").write_text("<?php\n$wp_version = '6.4.2';\n")
plugins = wproot / "wp-content" / "plugins"
plugins.mkdir(parents=True)
# vulnerable: wp-file-manager 6.5 (<6.9)
(plugins / "wp-file-manager").mkdir()
(plugins / "wp-file-manager" / "readme.txt").write_text("=== File Manager ===\nStable tag: 6.5\n")
# vulnerable: litespeed-cache 6.2 via php header (<6.4)
(plugins / "litespeed-cache").mkdir()
(plugins / "litespeed-cache" / "litespeed-cache.php").write_text(
    "<?php\n/*\nPlugin Name: LiteSpeed Cache\nVersion: 6.2\n*/\n")
# safe: contact-form-7 5.4.0 (>=5.3.2)
(plugins / "contact-form-7").mkdir()
(plugins / "contact-form-7" / "readme.txt").write_text("=== Contact Form 7 ===\nStable tag: 5.4.0\n")
# single-file plugin (wp-content/plugins/hello.php style) -> slug = file stem
(plugins / "hello.php").write_text(
    "<?php\n/**\n * Plugin Name: Hello Dolly\n * Version: 1.7.2\n */\n")
# a stray helper .php without a "Plugin Name:" header is NOT a plugin
(plugins / "index.php").write_text("<?php\n// Silence is golden.\n// Version: 9.9.9\n")
# must-use plugins: a directory and a single file
mu = wproot / "wp-content" / "mu-plugins"
(mu / "site-tweaks").mkdir(parents=True)
(mu / "site-tweaks" / "site-tweaks.php").write_text(
    "<?php\n/*\nPlugin Name: Site Tweaks\nVersion: 2.1.0\n*/\n")
(mu / "force-ssl.php").write_text("<?php\n/*\nPlugin Name: Force SSL\nVersion: 0.3\n*/\n")
# theme with no advisory
themes = wproot / "wp-content" / "themes" / "twentytwentyone"
themes.mkdir(parents=True)
(themes / "style.css").write_text("/*\nTheme Name: Twenty Twenty-One\nVersion: 1.0\n*/\n")

inv = wp.inventory(wproot)
check("core version detected", any(c.kind == "core" and c.version == "6.4.2" for c in inv))
check("inventory has 8 components (core + 3 dir plugins + 1 single-file + 2 mu + 1 theme)", len(inv) == 8)
plug = {c.slug: c.version for c in inv if c.kind == "plugin"}
check("single-file plugin inventoried by file stem with its Version header", plug.get("hello") == "1.7.2")
check("stray index.php without a Plugin Name header is not a plugin", "index" not in plug)
check("mu-plugin directory inventoried with Version header", plug.get("site-tweaks") == "2.1.0")
check("single-file mu-plugin inventoried with Version header", plug.get("force-ssl") == "0.3")

findings = wp.scan(wproot, feed)
ids = sorted((f.component.slug, f.advisory.cve) for f in findings)
print("   wp findings:", ids)
check("wp-file-manager 6.5 flagged (CVE-2020-25213)",
      ("wp-file-manager", "CVE-2020-25213") in ids)
check("litespeed-cache 6.2 flagged (CVE-2024-28000)",
      ("litespeed-cache", "CVE-2024-28000") in ids)
check("patched contact-form-7 5.4.0 NOT flagged",
      not any(f.component.slug == "contact-form-7" for f in findings))
check("2 wp findings total (base feed)", len(findings) == 2)

# --- scale: the full shipped feed carries thousands of WP advisories --------
full = FeedManager().current()
check("full feed has 5000+ WordPress advisories (NVD scale)", len(full.wp) >= 5000)
check("slug normalisation matches underscore NVD slugs to dash installs",
      wp._norm_slug("wp_file_manager") == wp._norm_slug("wp-file-manager"))
kinds = {a.type for a in full.wp}
check("full feed carries core and theme advisories, not only plugins",
      {"core", "plugin", "theme"} <= kinds)
# core matches by wp-includes/version.php: 4.7.0 is exposed to the REST API
# content-injection bug (CVE-2017-1001000, fixed 4.7.2); a patched 6.x is not.
core_old = Path(tempfile.mkdtemp(prefix="wp-")) / "wp"
(core_old / "wp-includes").mkdir(parents=True)
(core_old / "wp-includes" / "version.php").write_text("<?php\n$wp_version = '4.7.0';\n")
core_ids = {f.advisory.cve for f in wp.scan(core_old, full) if f.component.kind == "core"}
check("core 4.7.0 flagged for CVE-2017-1001000 via the full feed", "CVE-2017-1001000" in core_ids)
check("no fixed version listed inside its own affected range (full feed)",
      not any(wp.constraint_matches(fx, a.affected) for a in full.wp for fx in a.fixed))

# --- fleet report from mixed JSON -------------------------------------------
d = Path(tempfile.mkdtemp(prefix="rep-"))
(d / "web01.json").write_text(json.dumps({
    "summary": {}, "findings": [
        {"cve": "CVE-2026-109618", "verdict": "EXPOSED", "severity": "critical",
         "cvss": 9.2, "title": "php2shell", "fixed": "8.3.36", "exploited_in_wild": True}]}))
(d / "web02.json").write_text(json.dumps({
    "lockfile": "composer.lock", "vulnerable": [
        {"package": "phpmailer/phpmailer", "installed": "5.2.15", "cve": "CVE-2016-10033",
         "severity": "critical", "cvss": 9.8, "title": "RCE", "fixed": ["5.2.20"],
         "known_exploited": True}]}))
(d / "wpbox.json").write_text(json.dumps({
    "wordpress": "/var/www", "findings": [
        {"kind": "plugin", "slug": "wp-file-manager", "version": "6.5", "cve": "CVE-2020-25213",
         "severity": "critical", "cvss": 9.8, "title": "RCE", "fixed": ["6.9"],
         "known_exploited": True}]}))

rows = reportgen.load_rows([d / "web01.json", d / "web02.json", d / "wpbox.json"])
check("report aggregates 3 findings across hosts", len(rows) == 3)
check("report spans 3 hosts", len({r.host for r in rows}) == 3)
check("report normalises engine/composer/wp sources",
      {r.source for r in rows} == {"engine", "composer", "wp-plugin"})
html_out = reportgen.render_html(rows, feed.feed_version)
check("HTML report is well-formed-ish", html_out.startswith("<!doctype html>") and "fleet report" in html_out)
check("HTML shows host labels", "web01" in html_out and "wpbox" in html_out)
check("HTML counts 3 actively-exploited (KEV)", ">3</b><span>actively exploited (KEV)" in html_out)

# --- report: null / string numerics in EVERY doc type must not raise --------
(d / "nulls-scan.json").write_text(json.dumps({
    "summary": {}, "findings": [
        {"cve": "CVE-1", "verdict": "EXPOSED", "severity": None, "cvss": None,
         "epss": "0.42", "title": "t", "fixed": None}]}))
(d / "nulls-deps.json").write_text(json.dumps({
    "vulnerable": [
        {"package": "a/b", "installed": "1.0", "cve": "CVE-2", "severity": "high",
         "cvss": "n/a", "epss": None, "fixed": None, "reach": None}]}))
(d / "nulls-wp.json").write_text(json.dumps({
    "wordpress": "/x", "findings": [
        {"kind": "plugin", "slug": "p", "version": "1", "cve": "CVE-3",
         "cvss": None, "epss": "junk", "fixed": "6.9"}]}))
warns = []
nrows = reportgen.load_rows([d / "nulls-scan.json", d / "nulls-deps.json", d / "nulls-wp.json"],
                            warn=warns.append)
check("null cvss / string epss / null fixed never drop a finding (3 rows, 0 warnings)",
      len(nrows) == 3 and not warns)
check("null cvss coerces to 0.0 in every doc type", all(r.cvss == 0.0 for r in nrows))
check("string epss parses, junk epss -> None",
      {r.ident.split()[0]: r.epss for r in nrows} == {"CVE-1": 0.42, "a/b": None, "p": None})
check("null severity renders as unknown; null fixed renders as '-'",
      nrows and any(r.severity == "unknown" for r in nrows) and all(r.fixed in ("-", "6.9") for r in nrows))
check("report with null numerics still renders", "<table>" in reportgen.render_html(nrows))

print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
