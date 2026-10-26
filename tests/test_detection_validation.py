#!/usr/bin/env python3
"""Validation harness: precision/recall of the signature scanner on mixed traffic.

This is synthetic traffic, not production traffic (a true field validation needs
a live PHP host's logs). It measures that benign requests produce zero false
positives and known exploit lines are all caught.
"""
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phpwarden.detect import SignatureScanner  # noqa: E402
from phpwarden.feed import FeedManager  # noqa: E402

random.seed(1337)

# --- a realistic-ish benign access-log corpus (no exploit markers) ----------
PATHS = ["/", "/index.php", "/wp-login.php", "/api/v1/users?page=2",
         "/assets/app.js", "/autoload.php", "/search?q=php+tutorial",
         "/cart/checkout.php?step=3", "/blog/2026/10/release-notes",
         "/favicon.ico", "/robots.txt", "/admin/index.php?module=settings"]
UAS = ["Mozilla/5.0", "curl/8.4.0", "GoogleBot/2.1"]

def benign_line():
    ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    path = random.choice(PATHS)
    status = random.choice([200, 200, 200, 301, 404, 500])
    ua = random.choice(UAS)
    # include a logged cookie with PHPSESSID to try to trick the response-sig
    return f'{ip} - - [23/Oct/2026:10:00:00 +0000] "GET {path} HTTP/1.1" {status} 812 "-" "{ua}" cookie=PHPSESSID=8af3c0de9b12af34'

# --- known exploit lines (should all be caught on the access stream) --------
MALICIOUS = [
    '1.2.3.4 "GET /cgi-bin/php-cgi.exe?%ADd+auto_prepend_file%3dphp://input HTTP/1.1" 200',  # CVE-2024-4577
    '9.9.9.9 "GET /index.php/PHP%0Avalue HTTP/1.1" 200',                                      # CVE-2019-11043
    '5.5.5.5 "POST /?%add+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input HTTP/1.1" 200',  # 4577 variant
]

feed = FeedManager().current()
scanner = SignatureScanner(feed)

benign = [benign_line() for _ in range(2000)]
false_pos = [ln for ln in benign if scanner.scan_line(ln, stream="access")]
caught = [m for m in MALICIOUS if scanner.scan_line(m, stream="access")]

ok = True
def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and cond

print(f"benign lines: {len(benign)}, false positives: {len(false_pos)}")
print(f"malicious lines: {len(MALICIOUS)}, caught: {len(caught)}")
check("zero false positives on 2000 benign requests", len(false_pos) == 0)
check("all known exploit lines detected", len(caught) == len(MALICIOUS))

# response-signature must NOT fire when scanning the access stream
check("PHPSESSID in an access line does not trip the response-signature",
      all("response-signature" not in [h.kind for h in scanner.scan_line(b, stream="access")] for b in benign[:50]))
# but it does on the response stream (that is where it belongs)
resp_hit = scanner.scan_line('Set-Cookie: PHPSESSID=deadbeef', stream="response")
check("PHPSESSID response-signature fires on the response stream", len(resp_hit) >= 1)

if false_pos:
    print("  sample false positive:", false_pos[0])
print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
