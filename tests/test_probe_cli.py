#!/usr/bin/env python3
"""phpwarden probe: CLI wiring, ownership token flow, SSRF guard."""
import http.server, json, os, re, subprocess, sys, tempfile, threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from phpwarden import probe  # noqa: E402

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and bool(cond)

tmp = Path(tempfile.mkdtemp(prefix="pwprobe-"))
ENV = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PHPWARDEN_HOME=str(tmp / "home"), PHPWARDEN_FREE_FEED_URL="off")
STATE = {"token": None, "paths": [], "methods": set()}

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        STATE["paths"].append(self.path); STATE["methods"].add(self.command)
        if self.path == "/":
            body = '<html><head><meta name="generator" content="WordPress 6.4.2"></head><body>hi</body></html>'
        elif self.path == "/.well-known/phpwarden-verify.txt" and STATE["token"]:
            body = STATE["token"]
        elif self.path == "/.env":
            body = "APP_KEY=base64:SUPERSECRETVALUE\nDB_PASSWORD=hunter2hunter2\n"
        else:
            self.send_response(404); self.end_headers(); self.wfile.write(b"nope"); return
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(body.encode())
    do_HEAD = do_GET
    def do_POST(self):
        STATE["methods"].add("POST"); self.send_response(405); self.end_headers()
    def log_message(self, *a): pass

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{srv.server_address[1]}"

def run(*a):
    p = subprocess.run([sys.executable, "-m", "phpwarden.cli", "probe", *a], capture_output=True, text=True, env=ENV)
    return p.returncode, p.stdout, p.stderr

rc, out, _ = run(URL, "--print-token")
tok = re.search(r"phpwarden-verify=([0-9a-f]{32})", out)
check("--print-token shows the three ways and a 32-hex token, makes no request",
      rc == 0 and tok and ".well-known/phpwarden-verify.txt" in out and "<meta name" in out and STATE["paths"] == [])
tok = tok.group(1)
rc2, out2, _ = run(URL, "--print-token")
check("token is stable for the host on this machine", tok in out2)
mode = oct((tmp / "home" / "probe-secret").stat().st_mode & 0o777)
check("local secret file is 0600", mode == "0o600")
check("token differs per host", probe.local_token("a.example", tmp / "home") != probe.local_token("b.example", tmp / "home"))

STATE["paths"].clear()
rc, out, _ = run(URL, "--json", "--max-requests", "40")
d = json.loads(out)
check("unverified: passive mode; only the homepage and the ownership-file check are requested",
      d["mode"] == "passive" and STATE["paths"] == ["/", "/.well-known/phpwarden-verify.txt"])
check("unverified: no exposure findings", not any(f["kind"] in ("exposure", "endpoint") for f in d["findings"]))
rc, out, _ = run(URL)
check("unverified text output explains how to enable active checks", "--print-token" in out and "Passive only" in out)

STATE["token"] = tok; STATE["paths"].clear()
rc, out, _ = run(URL, "--json", "--max-requests", "40")
d = json.loads(out)
env = [f for f in d["findings"] if f["id"] == "exposed-env"]
check("verified by .well-known file: active mode", d["mode"] == "active" and d["ownership"] == {"verified": True, "method": "well-known"})
check("active: exposed .env is critical, exit code 1", env and env[0]["severity"] == "critical" and rc == 1)
check("active: secret values never appear in output", "SUPERSECRETVALUE" not in out and "hunter2" not in out and "APP_KEY" in out)
check("active: request budget respected", d["requests_made"] <= 40 and len(STATE["paths"]) <= 40)
check("only GET/HEAD were sent", STATE["methods"] <= {"GET", "HEAD"})
check("WordPress 6.4.2 matched against the feed", d["fingerprint"]["wordpress"] == "6.4.2"
      and any(f.get("cve") == "CVE-2026-87902" and f.get("known_exploited") for f in d["findings"]))
check("exploited findings are ranked first", d["findings"][0].get("known_exploited") is True)

STATE["paths"].clear()
rc, out, _ = run(URL, "--passive", "--json")
check("--passive stays passive even when verified", json.loads(out)["mode"] == "passive" and STATE["paths"] == ["/"])
rc, out, _ = run(URL, "--format", "sarif", "--max-requests", "40")
s = json.loads(out)
check("sarif output", s["version"] == "2.1.0" and s["runs"][0]["tool"]["driver"]["name"] == "phpwarden-probe"
      and len(s["runs"][0]["results"]) > 0)
rc, out, err = run("ftp://example.com")
check("non-http URL is exit 4", rc == 4)
rc, out, err = run("http://127.0.0.1:9", "--passive")
check("unreachable site is exit 4, not 'clean'", rc == 4 and "could not reach" in err)

check("is_public_host: loopback, private, link-local, metadata are refused",
      not any(probe.is_public_host(h) for h in ("127.0.0.1", "localhost", "10.0.0.5", "192.168.1.1",
                                                 "169.254.169.254", "::1", "[::1]", "0.0.0.0", "")))
check("is_public_host: a public address is allowed", probe.is_public_host("93.184.216.34"))
check("is_public_host: unresolvable name is refused", not probe.is_public_host("no-such-host.invalid"))

srv.shutdown()
print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
