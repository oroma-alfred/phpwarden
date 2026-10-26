#!/usr/bin/env python3
"""End-to-end test of the subscription: license -> feed update -> new coverage.

Spins a local HTTP server that acts as the licensed feed endpoint, serving a
newer feed with an extra CVE. Proves that `update()` pulls it, the cache takes
precedence, and the engine then assesses against the new CVE.
"""
import http.server
import json
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phpwarden.engine import Environment, assess  # noqa: E402
from phpwarden.feed import FeedManager  # noqa: E402
from phpwarden.vulndb import Feed  # noqa: E402
from phpwarden import version as V  # noqa: E402

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and cond

# Build a "newer" feed = bundled + one brand-new CVE, bumped feed_version.
base = Feed.bundled()
new_doc = {
    "feed_version": "2026.11.15", "schema": 1, "channel": "subscription",
    "generated": "2026-11-15",
    # a real maintained feed carries every category; the client refuses a feed
    # that would blank out Composer/WordPress coverage, so carry them through
    "composer_advisories": json.loads(Path(ROOT, "src/phpwarden/data/php-cve-feed.json").read_text())["composer_advisories"],
    "wp_advisories": json.loads(Path(ROOT, "src/phpwarden/data/php-cve-feed.json").read_text())["wp_advisories"],
    "cves": json.loads(Path(ROOT, "src/phpwarden/data/php-cve-feed.json").read_text())["cves"] + [{
        "id": "CVE-2026-55555", "title": "Hypothetical new FPM RCE", "class": "fpm-rce",
        "cvss": 9.1, "severity": "critical", "published": "2026-11-15",
        "exploited_in_wild": False, "sapi": ["any"], "os": ["any"],
        "branches": {"8.3": {"fixed": "8.3.40"}, "8.4": {"fixed": "8.4.30"}},
        "eol_affected": True, "exposure": [], "detectors": [],
        "remediation": "Upgrade to 8.3.40 / 8.4.30.", "references": []
    }]
}

AUTH = {"seen": None}
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        AUTH["seen"] = self.headers.get("Authorization")
        # the fake feed server rejects one specific key and 500s on another
        if self.headers.get("Authorization") == "Bearer REVOKED-KEY":
            self.send_response(401); self.end_headers(); self.wfile.write(b"bad key"); return
        if self.headers.get("Authorization") == "Bearer BROKEN-SERVER":
            self.send_response(500); self.end_headers(); self.wfile.write(b"oops"); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(new_doc).encode())
    def log_message(self, *a): pass

http.server.HTTPServer.allow_reuse_address = True
srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

tmp = Path(tempfile.mkdtemp(prefix="pwfeed-"))

# 1) No license -> stays on community feed.
fm0 = FeedManager(cache_dir=tmp, license_key=None)
r0 = fm0.update()
check("no license -> no_license status", r0["status"] == "no_license")
check("no license -> community feed still active", fm0.current().feed_version == base.feed_version)

st0 = fm0.status()
check("status without a key: license_key_set False, license_valid None, no legacy 'licensed'",
      st0["license_key_set"] is False and st0["license_valid"] is None and "licensed" not in st0)

# 2) With license -> pulls newer feed, sends the key, caches it.
fm = FeedManager(cache_dir=tmp, license_key="SUB-TEST-KEY",
                 feed_url=f"http://127.0.0.1:{PORT}/feed")
st1 = fm.status()
check("status with a key but before any update: license_key_set True, license_valid None",
      st1["license_key_set"] is True and st1["license_valid"] is None)
r = fm.update()
sent_auth = AUTH["seen"]          # snapshot: the rejected-key updates below overwrite it
check("licensed update -> updated", r["status"] == "updated")
check("update surfaces the server's HTTP status and license_valid True",
      r.get("http_status") == 200 and r.get("license_valid") is True)
check("status after an accepted update: license_valid True", fm.status()["license_valid"] is True)

# 2b) A rejected key is "unlicensed" (not a generic error) and the message says so.
fm_bad = FeedManager(cache_dir=Path(tempfile.mkdtemp(prefix="pwfeed-bad-")),
                     license_key="REVOKED-KEY", feed_url=f"http://127.0.0.1:{PORT}/feed")
rb = fm_bad.update()
check("401 from the feed server -> status unlicensed", rb["status"] == "unlicensed")
check("401 result carries http_status and license_valid False",
      rb.get("http_status") == 401 and rb.get("license_valid") is False)
check("401 message says the key was rejected", "rejected" in rb["message"] and "401" in rb["message"])
check("status after a rejected update: license_key_set True, license_valid False",
      fm_bad.status()["license_key_set"] is True and fm_bad.status()["license_valid"] is False)
check("rejected key leaves the community feed in effect",
      fm_bad.current().feed_version == base.feed_version)

# 2c) A non-auth HTTP error and a network error are both "error", and the
# HTTP one names its status code.
fm_500 = FeedManager(cache_dir=Path(tempfile.mkdtemp(prefix="pwfeed-500-")),
                     license_key="BROKEN-SERVER", feed_url=f"http://127.0.0.1:{PORT}/feed")
r5 = fm_500.update()
check("500 from the feed server -> status error with HTTP status in the message",
      r5["status"] == "error" and r5.get("http_status") == 500 and "HTTP 500" in r5["message"])
check("500 does not settle license validity", fm_500.status()["license_valid"] is None)
fm_net = FeedManager(cache_dir=Path(tempfile.mkdtemp(prefix="pwfeed-net-")),
                     license_key="ANY", feed_url="http://127.0.0.1:9/feed")   # discard port: refused
rn = fm_net.update()
check("network failure -> status error, no http_status",
      rn["status"] == "error" and "http_status" not in rn)
check("update reports the new CVE", "CVE-2026-55555" in r.get("added_cves", []))
check("license key was sent as a bearer token", sent_auth == "Bearer SUB-TEST-KEY")
check("active feed is now the subscription feed", fm.current().feed_version == "2026.11.15")
check("feed source reports subscription-cache", fm.source() == "subscription-cache")

# 3) The engine now assesses against the newly delivered CVE.
findings = assess(Environment(version=V.parse("8.3.20"), sapi="fpm", os="linux"), fm.current())
new_finding = next((f for f in findings if f.cve.id == "CVE-2026-55555"), None)
check("new CVE is now assessable", new_finding is not None)
check("8.3.20 exposed to the new CVE (fixed 8.3.40)",
      new_finding and new_finding.verdict == "EXPOSED")

# 4) Second update is a no-op (already current).
r2 = fm.update()
check("re-update -> current (no-op)", r2["status"] == "current")

srv.shutdown()
print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
