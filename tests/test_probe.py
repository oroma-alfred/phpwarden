#!/usr/bin/env python3
"""Validate the live-site probe against local fake sites on 127.0.0.1 only."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phpwarden import probe  # noqa: E402
from phpwarden.vulndb import Feed  # noqa: E402

feed = Feed.bundled()
ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and cond

TOKEN = probe.generate_token("127.0.0.1", "test-secret")

HOME = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.2" />
{meta}
<link rel='stylesheet' href='/wp-content/plugins/litespeed-cache/assets/css/style.css?ver=6.2' />
<script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>
<link rel='stylesheet' href='/wp-content/themes/twentytwentyfour/style.css?ver=1.0' />
</head><body>Hello</body></html>"""

VULN_FILES = {
    "/.env": (200, "APP_NAME=Demo\nAPP_KEY=secret\nDB_PASSWORD=hunter2supersecret\n"),
    "/.git/HEAD": (200, "ref: refs/heads/main\n"),
    "/xmlrpc.php": (200, "XML-RPC server accepts POST requests only."),
    "/wp-json/wp/v2/users": (200, json.dumps([{"id": 1, "slug": "admin-user-xyz", "name": "Admin"}])),
}


def make_handler(mode, state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            state["posts"] += 1
            self.send_response(405); self.end_headers()

        def do_GET(self):
            state["hits"].append(self.path)
            path = self.path.split("?")[0]
            if mode == "soft404":
                body = "<html><body>Welcome! Nothing here " + path + "</body></html>"
                self._send(200, body); return
            if mode == "offsite":
                self.send_response(302)
                self.send_header("Location", state["target"])
                self.end_headers(); return
            if path == "/":
                meta = state.get("meta", "")
                self._send(200, HOME.format(meta=meta), cookies=True); return
            if path == "/.well-known/phpwarden-verify.txt" and state.get("wellknown"):
                self._send(200, TOKEN + "\n"); return
            if path in VULN_FILES:
                code, body = VULN_FILES[path]
                self._send(code, body); return
            self._send(404, "Not Found")

        def _send(self, code, body, cookies=False):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "PHP/8.1.2")
            if cookies:
                self.send_header("Set-Cookie", "wordpress_test_cookie=WP%20Cookie; path=/")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return H


def serve(mode, **extra):
    state = {"hits": [], "posts": 0, **extra}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(mode, state))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, state, f"http://127.0.0.1:{srv.server_address[1]}/"


vuln, vstate, VURL = serve("vuln")
soft, sstate, SURL = serve("soft404", meta=None)

# --- token ------------------------------------------------------------------
check("generate_token is stable 32-hex",
      len(TOKEN) == 32 and TOKEN == probe.generate_token("127.0.0.1", "test-secret"))
check("generate_token differs per host", TOKEN != probe.generate_token("example.org", "test-secret"))

# --- passive ----------------------------------------------------------------
vstate["hits"].clear()
r = probe.run_probe(VURL, feed=feed, delay=0)
check("passive mode", r["mode"] == "passive")
check("passive makes exactly 1 request", r["requests_made"] == 1 and len(vstate["hits"]) == 1)
check("passive: no exposure/endpoint findings",
      all(f["kind"] in ("header", "tls", "vuln") for f in r["findings"]))
check("passive: header findings present (missing CSP)", any(f["id"] == "missing-csp" for f in r["findings"]))
check("passive: X-Powered-By disclosure reported", any(f["id"] == "disclosure-x-powered-by" for f in r["findings"]))
check("fingerprint php/wp/plugin", r["fingerprint"]["php"] == "8.1.2" and r["fingerprint"]["wordpress"] == "6.4.2"
      and r["fingerprint"]["plugins"].get("litespeed-cache") == "6.2")

# --- active refused without verification -----------------------------------
vstate["hits"].clear()
r = probe.run_probe(VURL, token=TOKEN, active=True, feed=feed, delay=0)
check("active refused without verification", r["mode"] == "passive" and not r["ownership"]["verified"])
check("refused run never requested .env", "/.env" not in vstate["hits"])
check("no POSTs ever sent", vstate["posts"] == 0)

# --- verification by .well-known -------------------------------------------
vstate["wellknown"] = True
ok_v, method = probe.verify_ownership(VURL, TOKEN)
check("verified by .well-known file", ok_v and method == "well-known")
check("wrong token not verified", probe.verify_ownership(VURL, "nope" * 8) == (False, None))
vstate["wellknown"] = False

# --- verification by meta + full active run --------------------------------
vstate["meta"] = f'<meta name="phpwarden-verify" content="{TOKEN}">'
vstate["hits"].clear()
r = probe.run_probe(VURL, token=TOKEN, feed=feed, delay=0)
ids = {f["id"]: f for f in r["findings"]}
check("verified by meta tag -> active", r["mode"] == "active" and r["ownership"]["method"] == "meta")
check(".env found", "exposed-env" in ids and ids["exposed-env"]["severity"] == "critical")
env_ev = ids.get("exposed-env", {}).get("evidence", "")
check(".env evidence names vars, no secret values",
      "APP_KEY" in env_ev and "secret" not in env_ev.replace("names only", "") and "hunter2" not in env_ev)
check(".git/HEAD found", "exposed-git-head" in ids)
check("xmlrpc found (medium)", ids.get("wp-xmlrpc", {}).get("severity") == "medium")
check("user enum reports count only", "wp-user-enum" in ids and "admin-user-xyz" not in json.dumps(r))
check("no false exposures for 404 paths", "exposed-phpinfo" not in ids and "exposed-backup-sql" not in ids)
core = [f for f in r["findings"] if f["kind"] == "vuln" and f["id"].endswith("-wordpress")]
check("WP 6.4.2 matched to a core advisory", len(core) >= 1)
ls = ids.get("vuln-CVE-2024-28000-litespeed-cache")
check("litespeed-cache 6.2 -> CVE-2024-28000 known_exploited", bool(ls) and ls["known_exploited"])
check("ranked: known_exploited first", r["findings"][0]["known_exploited"])
check("exit_code 1 for vulnerable site", probe.exit_code(r) == 1)
check("request count within default cap", r["requests_made"] <= 60)
check("no POSTs in active run", vstate["posts"] == 0)
txt = probe.to_text(r)
check("to_text marks exploited", "[EXPLOITED]" in txt and "CVE-2024-28000" in txt)

# --- SARIF ------------------------------------------------------------------
s = probe.to_sarif(r)
res = s["runs"][0]["results"]
check("SARIF shape", s["version"] == "2.1.0" and s["runs"][0]["tool"]["driver"]["name"] == "phpwarden-probe"
      and len(res) == len(r["findings"])
      and all(x["ruleId"] and x["level"] in ("error", "warning", "note")
              and x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("http")
              for x in res))
json.dumps(r); json.dumps(s)
check("result + SARIF are JSON-able", True)

# --- request cap ------------------------------------------------------------
vstate["hits"].clear()
r = probe.run_probe(VURL, token=TOKEN, feed=feed, delay=0, max_requests=5)
check("request cap honored", r["requests_made"] == 5 and len(vstate["hits"]) == 5)

# --- soft-404 ---------------------------------------------------------------
soft_token = TOKEN
sstate["hits"].clear()
# verify soft404 site via a fetch wrapper that injects the meta on the homepage only
def soft_fetch(url, **kw):
    resp = probe.default_fetch(url, **kw)
    if url.rstrip("/") == SURL.rstrip("/"):
        resp.body += f'<meta name="phpwarden-verify" content="{soft_token}">'.encode()
    return resp
r = probe.run_probe(SURL, token=soft_token, feed=feed, delay=0, fetch=soft_fetch)
check("soft-404 site probed actively", r["mode"] == "active")
check("soft-404 site yields no exposure/endpoint findings",
      not any(f["kind"] in ("exposure", "endpoint") for f in r["findings"]))
check("soft-404 noted", any("soft-404" in n for n in r["notes"]))

# --- never leave host on redirect ------------------------------------------
offsite, ostate, OURL = serve("offsite", target=SURL.replace("127.0.0.1", "localhost") + "evil")
sstate["hits"].clear()
ostate["meta"] = None
r = probe.run_probe(OURL, token=TOKEN, active=True, feed=feed, delay=0)
s2 = probe._Session(OURL, None, 10, 0)
s2.get(OURL)
check("redirect to other host not followed", len(sstate["hits"]) == 0
      and any("another host" in n for n in s2.notes))

# --- unreachable target -----------------------------------------------------
r = probe.run_probe("http://127.0.0.1:1/", feed=feed, delay=0)
check("unreachable target handled", r["findings"] == [] or all(f["kind"] != "exposure" for f in r["findings"]))

for srv in (vuln, soft, offsite):
    srv.shutdown()
print("RESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
