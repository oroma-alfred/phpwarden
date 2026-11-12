#!/usr/bin/env python3
"""Merge imported engine CVE entries into the curated base (curated wins).

  python3 -I merge_engine_cves.py --base base/php-cve-feed.base.json \
      --imported output/engine_news.json [--kev-seen ../data/kev-seen.json] \
      [--shipped ../src/phpwarden/data/php-cve-feed.json]

Rules:
  * a CVE already in the base keeps every curated field (SAPI/OS gating,
    exposure checks, detectors, remediation text); only branches the curated
    entry lacks are added from the import, never overwritten;
  * new CVEs are appended as imported;
  * exploited_in_wild / known_exploited / epss come from the KEV+EPSS snapshot
    (data/kev-seen.json) when given, so an offline merge still ranks by
    exploitation. enrich.py re-applies live KEV/EPSS on the server.
  * with --shipped, the shipped feed's "cves" array is replaced by the merged
    list (its composer/wp arrays are left untouched) and feed_version is bumped
    with a ".N" suffix so clients see it as newer.
"""
import argparse
import datetime as dt
import json
from pathlib import Path


def _vt(v):
    return tuple(int(x) for x in v.split("."))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--imported", required=True)
    ap.add_argument("--kev-seen")
    ap.add_argument("--shipped")
    a = ap.parse_args()

    base = json.loads(Path(a.base).read_text())
    imported = json.loads(Path(a.imported).read_text())["cves"]
    seen = {}
    if a.kev_seen:
        try:
            seen = json.loads(Path(a.kev_seen).read_text()).get("seen", {})
        except (OSError, ValueError):
            pass

    by_id = {c["id"]: c for c in base.get("cves", [])}
    added = branches_added = 0
    for imp in imported:
        cur = by_id.get(imp["id"])
        if cur is None:
            by_id[imp["id"]] = imp
            added += 1
            continue
        for b, v in imp["branches"].items():
            if b not in cur.setdefault("branches", {}):
                cur["branches"][b] = v
                branches_added += 1
        for k in ("description", "aka"):
            if not cur.get(k) and imp.get(k):
                cur[k] = imp[k]

    for cid, c in by_id.items():
        s = seen.get(cid)
        if not s:
            continue
        if s.get("kev"):
            c["exploited_in_wild"] = True
            c["known_exploited"] = True
        if s.get("epss") is not None and c.get("epss") is None:
            c["epss"] = s["epss"]

    merged = sorted(by_id.values(), key=lambda c: (c.get("published", ""), c["id"]), reverse=True)
    base["cves"] = merged
    Path(a.base).write_text(json.dumps(base, indent=1) + "\n")
    print(f"base: {len(merged)} engine CVEs (+{added} new, {branches_added} branches filled on curated entries)")

    if a.shipped:
        feed = json.loads(Path(a.shipped).read_text())
        feed["cves"] = merged
        today = dt.date.today().strftime("%Y.%m.%d")
        last = str(feed.get("feed_version", ""))
        n = int(last.rsplit(".", 1)[1]) + 1 if last.startswith(today + ".") and last.rsplit(".", 1)[1].isdigit() else 1
        feed["feed_version"] = f"{today}.{n}"
        feed["generated"] = dt.date.today().isoformat()
        feed["source"] = feed.get("source", "").replace("curated base", "curated base + php-src NEWS", 1) \
            if "php-src NEWS" not in feed.get("source", "") else feed["source"]
        Path(a.shipped).write_text(json.dumps(feed, indent=1))
        print(f"shipped: {a.shipped} -> feed_version {feed['feed_version']}, {len(merged)} engine CVEs")


if __name__ == "__main__":
    main()
