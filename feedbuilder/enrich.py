#!/usr/bin/env python3
"""Enrich the feed with real-world exploitation data (stdlib only).

Joins two open, authoritative sources by CVE id:
  * CISA KEV  -> known_exploited (+ ransomware campaign flag)
  * FIRST EPSS -> epss probability and percentile (likelihood of exploitation)

This is the prioritisation layer: findings get ranked by whether they are
actually being exploited, not just by CVSS. Entries without a CVE id (GHSA-only
FriendsOfPHP advisories keyed by date) are left as-is.

Usage:
  python3 -I enrich.py --feed <feed.json> --kev kev.json --epss epss.csv \
      --out <feed.json> --feed-version 2026.10.23.2
"""
import argparse
import csv
import json
from pathlib import Path


# KEV vendor/product words that mean "this should be in a PHP feed". Used only
# to warn about gaps (a KEV CVE we never marked because no upstream mapped it to
# a package); the fix is a curated entry in base/php-cve-feed.base.json.
_PHP_HINTS = ("php", "magento", "adobe commerce", "wordpress", "drupal", "joomla",
              "laravel", "symfony", "craft cms", "typo3", "prestashop", "moodle",
              "phpmailer", "roundcube", "vbulletin", "woocommerce", "opencart")


def kev_gaps(doc, feed_ids, days=None, today=None):
    """KEV entries that look PHP-related but aren't in the feed."""
    import datetime as _dt
    today = today or _dt.date.today()
    out = []
    for v in doc.get("vulnerabilities", []):
        cid = v.get("cveID") or ""
        text = f"{v.get('vendorProject','')} {v.get('product','')}".lower()
        if cid in feed_ids or not any(h in text for h in _PHP_HINTS):
            continue
        if days is not None:
            try:
                if (today - _dt.date.fromisoformat(str(v.get("dateAdded"))[:10])).days > days:
                    continue
            except ValueError:
                pass
        out.append((cid, v.get("vendorProject", ""), v.get("product", ""), str(v.get("dateAdded", ""))[:10]))
    return out


def load_kev(path):
    doc = json.loads(Path(path).read_text())
    kev, ransom = {}, set()
    for v in doc.get("vulnerabilities", []):
        cid = v.get("cveID")
        if cid:
            kev[cid] = str(v.get("dateAdded") or "")[:10]     # when CISA listed it
            if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known":
                ransom.add(cid)
    return kev, ransom


def load_epss(path):
    scores = {}
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or row[0] == "cve":
                continue
            try:
                scores[row[0]] = (float(row[1]), float(row[2]))
            except (ValueError, IndexError):
                continue
    return scores


def _enrich_list(items, id_key, kev, ransom, epss):
    n_kev = n_epss = 0
    for it in items:
        cid = it.get(id_key)
        if not cid or not str(cid).startswith("CVE-"):
            continue
        if cid in kev:
            it["known_exploited"] = True
            if kev[cid]:
                it["kev_added"] = kev[cid]
            n_kev += 1
            if cid in ransom:
                it["ransomware"] = True
        if cid in epss:
            it["epss"], it["epss_percentile"] = epss[cid]
            n_epss += 1
    return n_kev, n_epss


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed", required=True)
    ap.add_argument("--kev", required=True)
    ap.add_argument("--epss", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--feed-version", required=True)
    a = ap.parse_args()

    feed = json.loads(Path(a.feed).read_text())
    kev, ransom = load_kev(a.kev)
    epss = load_epss(a.epss)

    totals = {"kev": 0, "epss": 0}
    for section, idk in (("cves", "id"), ("composer_advisories", "cve"), ("wp_advisories", "cve")):
        k, e = _enrich_list(feed.get(section, []), idk, kev, ransom, epss)
        totals["kev"] += k
        totals["epss"] += e

    ids = {it.get(k) for sec, k in (("cves", "id"), ("composer_advisories", "cve"),
                                    ("wp_advisories", "cve")) for it in feed.get(sec, [])}
    gaps = kev_gaps(json.loads(Path(a.kev).read_text()), ids, days=365)
    for cid, vendor, product, added in gaps:
        print(f"  KEV GAP: {cid} ({vendor} {product}, KEV {added}) is not in the feed")
    feed["feed_version"] = a.feed_version
    feed["enriched"] = {"kev_source": "CISA KEV", "epss_source": "FIRST EPSS"}
    Path(a.out).write_text(json.dumps(feed, indent=1))
    print(f"enriched -> {a.out} (feed {a.feed_version})")
    print(f"  marked known-exploited (KEV): {totals['kev']}")
    print(f"  scored with EPSS:             {totals['epss']}")


if __name__ == "__main__":
    main()
