#!/usr/bin/env python3
"""Probe correctness on local fixture sites (stdlib only; nothing leaves 127.0.0.1).

  bench.py <repo root>

Seven small sites are served on loopback. For each, `phpwarden probe` runs in
active mode (the site proves ownership with the meta tag) and its exposure and
endpoint findings are compared with what was actually planted.
"""
import http.server
import json
import secrets
import sys
import threading
from pathlib import Path

REPO = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(REPO / "src"))
from phpwarden import probe  # noqa: E402
from phpwarden.vulndb import Feed  # noqa: E402

TOKEN = "b" * 32
META = f'<meta name="phpwarden-verify" content="{TOKEN}">'
GOOD_HEADERS = {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
HOME = f"<html><head>{META}<title>Shop</title></head><body><h1>Welcome</h1></body></html>"

# Every check the probe has, with content that really is the sensitive thing.
PLANTED = {
    "/.env": "APP_KEY=base64:c2VjcmV0c2VjcmV0\nDB_PASSWORD=not-a-real-password\nMAIL_HOST=smtp\n",
    "/.env.backup": "APP_KEY=base64:c2VjcmV0c2VjcmV0\nDB_PASSWORD=not-a-real-password\n",
    "/.git/HEAD": "ref: refs/heads/main\n",
    "/.git/config": "[core]\n\trepositoryformatversion = 0\n",
    "/composer.lock": json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.5.0"}], "packages-dev": []}),
    "/composer.json": json.dumps({"require": {"php": ">=8.1"}}),
    "/phpinfo.php": "<html><title>phpinfo()</title><h1>PHP Version 8.3.1</h1></html>",
    "/info.php": "<html><title>phpinfo()</title><h1>PHP Version 8.3.1</h1></html>",
    "/wp-config.php.bak": "<?php define('DB_NAME','x'); define('DB_PASSWORD','not-real');",
    "/wp-config.php~": "<?php define('DB_NAME','x'); define('DB_PASSWORD','not-real');",
    "/wp-config.php.save": "<?php define('DB_NAME','x'); define('DB_PASSWORD','not-real');",
    "/.DS_Store": b"\x00\x00\x00\x01Bud1\x00\x00",
    "/backup.zip": b"PK\x03\x04\x14\x00\x00\x00",
    "/backup.sql": "-- MySQL dump 10.13\nCREATE TABLE users (id int);\n",
    "/database.sql": "-- MySQL dump 10.13\nINSERT INTO users VALUES (1);\n",
    "/debug.log": "[14-Nov-2026 10:00:00 UTC] PHP Warning:  Undefined variable $x in /var/www/a.php on line 3\n",
    "/wp-content/debug.log": "[14-Nov-2026 10:00:00 UTC] PHP Fatal error:  Uncaught Error in /var/www/b.php:9\n",
    "/storage/logs/laravel.log": "[2026-11-14 10:00:00] production.ERROR: SQLSTATE[HY000] {\"exception\":\"...\"}\n",
    "/error_log": "[14-Nov-2026 10:00:00 UTC] PHP Notice:  Undefined index: q in /var/www/c.php on line 1\n",
    "/_ignition/health-check": json.dumps({"can_execute_commands": True}),
    "/telescope": "<html><title>Telescope - Laravel Telescope</title></html>",
    "/horizon": "<html><title>Horizon - Laravel Horizon</title></html>",
    "/_profiler": "<html><title>Symfony Profiler</title><div class='sf-toolbar'></div></html>",
    "/app_dev.php": "<html><body>Welcome to Symfony<div class='sf-toolbar'></div></body></html>",
    "/adminer.php": "<html><title>Login - Adminer</title></html>",
    "/phpmyadmin/": "<html><title>phpMyAdmin</title></html>",
    "/xmlrpc.php": "XML-RPC server accepts POST requests only.",
    "/wp-json/wp/v2/users": json.dumps([{"id": 1, "slug": "zq-first-user"}, {"id": 2, "slug": "zq-second-user"}]),
    "/server-status": "<html><title>Apache Status</title><h1>Apache Server Status for example</h1></html>",
}
EXPECTED = ({c[0] for c in probe.EXPOSURE_CHECKS} | {c[0] for c in probe.ENDPOINT_CHECKS})
# Files that exist at the sensitive paths but are NOT the sensitive thing.
DECOYS = {
    "/.env": "<html><body>Access to this resource is restricted.</body></html>",
    "/.git/HEAD": "<html><body>Nothing to see</body></html>",
    "/composer.json": "{}",
    "/composer.lock": "[]",
    "/phpinfo.php": "<html><body>This page was removed. See the PHP manual for phpinfo.</body></html>",
    "/backup.zip": "<html><body>Download expired</body></html>",
    "/backup.sql": "<html><body>How to CREATE TABLE in SQL: a tutorial</body></html>",
    "/debug.log": "no errors today\n",
    "/wp-config.php.bak": "<html><body>404</body></html>",
    "/xmlrpc.php": "<html><body>XML-RPC is disabled on this site.</body></html>",
    "/wp-json/wp/v2/users": json.dumps({"code": "rest_user_cannot_view", "data": {"status": 401}}),
    "/telescope": "<html><body>Please log in</body></html>",
    "/phpmyadmin/": "<html><body>Please log in</body></html>",
    "/server-status": "<html><body>Our status page: all systems operational</body></html>",
    "/_ignition/health-check": "<html><body>Not found</body></html>",
}
NAV = ("<nav>Hosting · phpMyAdmin · Adminer · Laravel Horizon · Laravel Telescope · Symfony · "
       "Apache Server Status · PHP Version 8.3 phpinfo guide</nav>")


def site(kind):
    """kind -> a handler class."""
    class H(http.server.BaseHTTPRequestHandler):
        count = 0
        methods = set()

        def _send(self, code, body, ctype="text/html", headers=None):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**GOOD_HEADERS, **(headers or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            type(self).count += 1
            type(self).methods.add(self.command)
            path = self.path.split("?")[0]
            if kind == "soft404-static":
                return self._send(200, HOME)
            if kind == "soft404-dynamic":      # reflects the path, random nonce, tech words in the nav
                return self._send(200, f"<html><head>{META}</head><body>{NAV}<p>No page at {path}</p>"
                                       f"<script nonce='{secrets.token_hex(12)}'></script>"
                                       f"<!-- rendered {secrets.token_hex(8)} --></body></html>")
            if path == "/":
                return self._send(200, HOME)
            if kind == "redirect-login":
                if path == "/login":
                    return self._send(200, f"<html><body>{NAV}<form>Sign in</form></body></html>")
                return self._send(302, "", headers={"Location": "/login"})
            if kind == "forbidden":
                return self._send(403, "<html><body>Forbidden</body></html>")
            table = PLANTED if kind == "planted" else DECOYS if kind == "decoys" else {}
            if path in table:
                return self._send(200, table[path], "application/octet-stream" if isinstance(table[path], bytes) else "text/plain")
            return self._send(404, "<html><body>Not found</body></html>")
        do_HEAD = do_GET

        def do_POST(self):
            type(self).methods.add("POST")
            self._send(405, "")

        def log_message(self, *a):
            pass
    return H


SITES = [
    ("clean", "404 for everything but the homepage", set()),
    ("forbidden", "403 for everything but the homepage", set()),
    ("soft404-static", "200 with the same page for every path", set()),
    ("soft404-dynamic", "200 for every path; page echoes the path, has a random nonce and a nav naming phpMyAdmin, Adminer, Horizon...", set()),
    ("redirect-login", "every path redirects to /login (200, nav names the same tools)", set()),
    ("decoys", "15 sensitive paths exist but hold harmless content", set()),
    ("planted", "all 29 exposures and endpoints really present", EXPECTED),
]


def main():
    feed = Feed.bundled()
    print(f"{'site':<17}{'mode':<9}{'requests':>9}{'expected':>10}{'found':>7}{'true+':>7}{'false+':>7}{'missed':>8}  only GET/HEAD")
    totals = [0, 0, 0, 0]
    detail = []
    for kind, desc, expected in SITES:
        H = site(kind)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}/"
        res = probe.run_probe(url, token=TOKEN, feed=feed, delay=0, tls_check=lambda h, p: None)
        srv.shutdown()
        found = {f["id"] for f in res["findings"] if f["kind"] in ("exposure", "endpoint")}
        tp, fp, fn = found & expected, found - expected, expected - found
        for i, n in enumerate((len(expected), len(tp), len(fp), len(fn))):
            totals[i] += n
        print(f"{kind:<17}{res['mode']:<9}{res['requests_made']:>9}{len(expected):>10}{len(found):>7}{len(tp):>7}"
              f"{len(fp):>7}{len(fn):>8}  {'yes' if H.methods <= {'GET', 'HEAD'} else 'NO: ' + str(H.methods)}")
        detail.append((kind, desc, sorted(fp), sorted(fn), res["notes"],
                       sorted(f["id"] for f in res["findings"] if f["kind"] not in ("exposure", "endpoint"))))
    print(f"{'TOTAL':<17}{'':<9}{'':>9}{totals[0]:>10}{'':>7}{totals[1]:>7}{totals[2]:>7}{totals[3]:>8}")
    print()
    for kind, desc, fp, fn, notes, other in detail:
        print(f"{kind}: {desc}")
        if fp:
            print(f"  FALSE POSITIVES: {', '.join(fp)}")
        if fn:
            print(f"  MISSED: {', '.join(fn)}")
        if other:
            print(f"  other findings (headers, versions): {', '.join(other)}")
        if notes:
            print(f"  notes: {'; '.join(notes)}")
    # secrets must never be echoed
    H = site("planted")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    res = probe.run_probe(f"http://127.0.0.1:{srv.server_address[1]}/", token=TOKEN, feed=feed, delay=0,
                          tls_check=lambda h, p: None)
    srv.shutdown()
    dump = json.dumps(res) + probe.to_text(res)
    leaked = [s for s in ("not-a-real-password", "c2VjcmV0c2VjcmV0", "not-real", "zq-first-user", "zq-second-user") if s in dump]
    print(f"\nsecret values or usernames echoed in the output: {leaked or 'none'}")
    # unverified site: passive only
    H = site("planted")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    res = probe.run_probe(f"http://127.0.0.1:{srv.server_address[1]}/", token="c" * 32, feed=feed, delay=0,
                          tls_check=lambda h, p: None)
    srv.shutdown()
    n = sum(1 for f in res["findings"] if f["kind"] in ("exposure", "endpoint"))
    print(f"planted site with the WRONG token: mode={res['mode']}, {H.count} request(s) reached the server, "
          f"{n} exposure/endpoint findings")


if __name__ == "__main__":
    main()
