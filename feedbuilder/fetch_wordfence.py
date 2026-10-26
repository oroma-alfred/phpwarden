#!/usr/bin/env python3
"""Fetch the Wordfence Intelligence v3 vulnerability feed with an API key.

Interim licensed source. The current v3 endpoint requires authentication (it
returns 401 without a key). Get a free key from
https://www.wordfence.com/threat-intel/ and set WORDFENCE_API_KEY; this saves
the raw feed JSON, which import_wordfence.py then maps into wp_advisories.

Independence note: the long-term, license-free WordPress source is NVD/CVE
(see import_nvd_wordpress.py). This fetcher is for the interim while that
coverage grows.

Usage:
  WORDFENCE_API_KEY=... python3 -I fetch_wordfence.py <out.json>
"""
import os
import sys
import urllib.request

# v3 base; exact path/params are confirmed against the account's API docs once a
# key is in hand. Both header-bearer and query-key styles are attempted.
V3_URL = os.environ.get(
    "WORDFENCE_FEED_URL",
    "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production")


def fetch(key: str) -> bytes:
    attempts = [
        {"headers": {"Authorization": f"Bearer {key}"}, "url": V3_URL},
        {"headers": {"x-api-key": key}, "url": V3_URL},
        {"headers": {}, "url": V3_URL + ("&" if "?" in V3_URL else "?") + "k=" + key},
    ]
    last = None
    for a in attempts:
        req = urllib.request.Request(a["url"],
                                     headers={"User-Agent": "phpwarden-feed/1", **a["headers"]})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
                return resp.read()
        except Exception as e:  # noqa: BLE001
            last = e
    raise SystemExit(f"Wordfence v3 fetch failed (check key/endpoint): {last}")


def main():
    if len(sys.argv) != 2:
        print(__doc__); return 2
    key = os.environ.get("WORDFENCE_API_KEY")
    if not key:
        print("set WORDFENCE_API_KEY (free key from wordfence.com/threat-intel)", file=sys.stderr)
        return 2
    raw = fetch(key)
    out = sys.argv[1]
    with open(out, "wb") as fh:
        fh.write(raw)
    print(f"fetched {len(raw)} bytes -> {out}  (now run import_wordfence.py on it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
