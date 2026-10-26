#!/usr/bin/env python3
"""Page the NVD CVE 2.0 API for WordPress CVEs and save the raw pages (stdlib).

License-free: NVD is U.S. public-domain data. Respects NVD rate limits (5 req /
30 s without a key; set NVD_API_KEY for 50 / 30 s). Saves one JSON file per
page into an output directory for import_nvd_wordpress.py.

Usage:
  python3 -I fetch_nvd_wordpress.py <out-dir> [max_pages]
"""
import json
import os
import sys
import time
import urllib.request
import urllib.parse
from pathlib import Path

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000


def fetch_page(start, key=None):
    params = {"keywordSearch": "wordpress", "resultsPerPage": PAGE, "startIndex": start}
    url = BASE + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "phpwarden-feedbuilder/1"})
    if key:
        req.add_header("apiKey", key)
    with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310
        return json.loads(r.read())


def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
    max_pages = int(sys.argv[2]) if len(sys.argv) > 2 else 999
    key = os.environ.get("NVD_API_KEY")
    delay = 2.0 if key else 6.5          # stay within the rate limit

    start, total, pages = 0, None, 0
    while pages < max_pages:
        for attempt in range(4):
            try:
                doc = fetch_page(start, key)
                break
            except Exception as e:  # noqa: BLE001 — transient; back off and retry
                print(f"  page @{start} attempt {attempt+1} failed: {e.__class__.__name__}; backing off")
                time.sleep(delay * (attempt + 2))
        else:
            print(f"giving up on page @{start}")
            break
        total = doc.get("totalResults", 0)
        got = len(doc.get("vulnerabilities", []))
        (out / f"nvd-wp-{start:06d}.json").write_text(json.dumps(doc))
        pages += 1
        print(f"  saved page @{start}: {got} CVEs (total {total})")
        start += PAGE
        if start >= total or got == 0:
            break
        time.sleep(delay)
    print(f"done: {pages} pages, up to {total} CVEs -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
