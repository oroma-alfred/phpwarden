#!/usr/bin/env python3
"""CLI edge cases: exit codes, --out failures, --report-to failures, feed status.

Runs the real `phpwarden` entry point in subprocesses with an isolated
PHPWARDEN_HOME so no user cache is read or written.
"""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

ok = True


def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and cond


HOME = Path(tempfile.mkdtemp(prefix="pw-cli-home-"))
ENV = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PHPWARDEN_HOME=str(HOME))
ENV.pop("PHPWARDEN_LICENSE", None)
ENV.pop("PHPWARDEN_REPORT_URL", None)
ENV.pop("PHPWARDEN_REPORT_TOKEN", None)


def run(*args, env=None):
    p = subprocess.run([sys.executable, "-m", "phpwarden.cli", *args],
                       capture_output=True, text=True, env=env or ENV, cwd=str(ROOT))
    return p.returncode, p.stdout, p.stderr


# --- 3: usage errors exit 64 (EX_USAGE), never 2 ------------------------------
rc, out, err = run("scan", "--bogus-flag")
check("unknown flag exits 64", rc == 64)
check("usage error message goes to stderr", "error:" in err and "--bogus-flag" in err and not out)
rc, out, err = run()
check("no subcommand exits 64", rc == 64)
rc, out, err = run("deps")
check("missing positional exits 64", rc == 64)
rc, out, err = run("scan", "--sapi", "nope", "--version", "8.3.0")
check("bad --sapi choice exits 64", rc == 64)
rc, out, err = run("--help")
check("--help exits 0 and documents the exit codes", rc == 0 and "64 usage error" in out and "5  --report-to" in out)
rc, out, err = run("scan", "--help")
check("subcommand --help exits 0 (subparser inherits _Parser)", rc == 0 and "usage: phpwarden scan" in out)

# --- 5: rules/report --out into a missing directory -> error + exit 4 ---------
rc, out, err = run("rules", "--out", "/nonexistent/dir/x.conf")
check("rules --out to a missing dir exits 4", rc == 4)
check("rules --out failure is a one-line error, not a traceback",
      err.startswith("error: cannot write /nonexistent/dir/x.conf:") and "Traceback" not in err)
good = HOME / "rules.conf"
rc, out, err = run("rules", "--out", str(good))
check("rules --out to a writable path still exits 0 and writes", rc == 0 and good.exists() and "SecRule" in good.read_text())
rc, out, err = run("report", str(good), "--out", "/nonexistent/dir/fleet.html")
check("report --out to a missing dir exits 4 with the same error shape",
      rc == 4 and err.rstrip().endswith("No such file or directory") and "Traceback" not in err)

# --- 3b: a failed --report-to upload is exit 5 on a clean run, local output first
SEEN = {"posts": 0}


class Ingest(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        SEEN["posts"] += 1
        if self.path.endswith("/broken"):
            self.send_response(500); self.end_headers(); self.wfile.write(b"boom"); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"stored": 1}).encode())

    def log_message(self, *a):
        pass


http.server.HTTPServer.allow_reuse_address = True
srv = http.server.HTTPServer(("127.0.0.1", 0), Ingest)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
GOOD_URL = f"http://127.0.0.1:{PORT}/ingest"
BAD_URL = f"http://127.0.0.1:{PORT}/broken"
DEAD_URL = "http://127.0.0.1:9/ingest"          # discard port: connection refused

clean_lock = HOME / "clean.lock"
clean_lock.write_text(json.dumps({"packages": [{"name": "acme/nothing-known", "version": "1.0.0"}]}))
vuln_lock = HOME / "vuln.lock"
vuln_lock.write_text(json.dumps({"packages": [{"name": "adodb/adodb-php", "version": "5.20.0"}]}))

rc, out, err = run("deps", str(clean_lock), "--no-reachability", "--report-to", GOOD_URL)
check("clean deps + successful upload exits 0", rc == 0 and "reported to" in err)
rc, out, err = run("deps", str(clean_lock), "--no-reachability", "--report-to", BAD_URL)
check("clean deps + HTTP 500 upload exits 5", rc == 5)
check("local results are still printed before the upload failure",
      "No known-vulnerable Composer packages" in out and "report-to failed (HTTP 500)" in err)
rc, out, err = run("deps", str(clean_lock), "--no-reachability", "--report-to", DEAD_URL)
check("clean deps + network error on upload exits 5", rc == 5 and "report-to failed" in err)
rc, out, err = run("deps", str(vuln_lock), "--no-reachability", "--report-to", BAD_URL)
check("vulnerable deps + failed upload keeps exit 1 (local result wins)", rc == 1 and "vulnerable package" in out)
rc, out, err = run("scan", "--version", "8.3.99", "--sapi", "fpm", "--os", "linux", "--report-to", BAD_URL)
check("scan shares _maybe_report: failed upload turns a clean/possible result non-zero",
      rc in (2, 5) and "report-to failed" in err and "phpwarden" in out)
log = HOME / "access.log"
log.write_text('1.2.3.4 - - [24/Oct/2026:01:02:03 +0000] "GET /index.php HTTP/1.1" 200 5 "-" "curl/8"\n')
rc, out, err = run("detect", str(log), "--report-to", BAD_URL)
check("detect shares _maybe_report: clean log + failed upload exits 5", rc == 5 and "No exploitation signatures" in out)
wproot = HOME / "wp"
(wproot / "wp-content" / "plugins").mkdir(parents=True)
rc, out, err = run("wordpress", str(wproot), "--report-to", BAD_URL)
check("wordpress shares _maybe_report: clean install + failed upload exits 5", rc == 5 and "WordPress at" in out)
check("every failing upload actually reached the ingest server", SEEN["posts"] >= 5)

# --- 1a via the CLI: --project at a missing dir -> reach "unknown" ----------
rc, out, err = run("deps", str(vuln_lock), "--project", str(HOME / "nope"), "--json")
doc = json.loads(out)
check("deps --json with a missing --project marks every finding reach=unknown",
      rc == 1 and doc["vulnerable"] and all(f["reach"] == "unknown" for f in doc["vulnerable"]))

# --- 4 via the CLI: feed status / feed update surface the license state -----
rc, out, err = run("feed", "status", "--json")
st = json.loads(out)
check("feed status (no key): license_key_set False, license_valid None, no 'licensed'",
      rc == 0 and st["license_key_set"] is False and st["license_valid"] is None and "licensed" not in st)
env_key = dict(ENV, PHPWARDEN_LICENSE="not-a-real-key", PHPWARDEN_FEED_URL=f"http://127.0.0.1:{PORT}/feed")


class Reject(Ingest):
    def do_GET(self):
        self.send_response(403); self.end_headers(); self.wfile.write(b"revoked")


srv.RequestHandlerClass = Reject
rc, out, err = run("feed", "status", "--json", env=env_key)
st = json.loads(out)
check("feed status (key set, never checked): license_key_set True, license_valid None",
      st["license_key_set"] is True and st["license_valid"] is None)
rc, out, err = run("feed", "status", env=env_key)
check("feed status text names license_key_set and an unknown validity",
      "license_key_set=True" in out and "license_valid=unknown" in out)
rc, out, err = run("feed", "update", env=env_key)
check("feed update against a 403 exits 1 and reports unlicensed [HTTP 403]",
      rc == 1 and out.startswith("unlicensed [HTTP 403]:") and "rejected" in out)
rc, out, err = run("feed", "status", "--json", env=env_key)
st = json.loads(out)
check("feed status after the rejected update: license_valid False", st["license_valid"] is False)
rc, out, err = run("feed", "status", env=env_key)
check("feed status text says REJECTED after a rejected update", "license_valid=REJECTED" in out)
rc, out, err = run("feed", "update", env=ENV)
check("no_license path unchanged: exit 0 with the community-feed message",
      rc == 0 and out.startswith("No license key set."))

srv.shutdown()
print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
