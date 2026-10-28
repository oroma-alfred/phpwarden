#!/usr/bin/env python3
"""Merge the curated base feed with imported bulk advisories into the shipped feed.

Build tooling (stdlib only; imports the runtime matcher from ../src so the
feed is validated with exactly the code that will read it). Curated entries
always win over imported ones for the same (package, cve) so hand-tuned CVSS /
exposure / detectors are preserved; imported entries fill out the long tail.

Merge rules, per (package, cve) for Composer and per (slug, cve) for WordPress
(slugs compared with "_" == "-", the wordpress.org convention):
  * affected ranges are unioned (OR-groups deduplicated)
  * known_exploited / ransomware are OR-ed, cvss / epss take the max
  * an "unknown" severity is filled from any source that knows one
  * "fixed" is the union, then filtered to versions that are NOT inside the
    merged affected range (a branch end like "<2.3.0" is not a fix when 2.3.0
    is itself affected) — the same matcher the scanner uses decides
  * OR-groups with a version the matcher cannot parse are dropped (and an
    advisory left with no group is dropped)

Usage:
  python3 -I build_feed.py \
      --base feedbuilder/base/php-cve-feed.base.json \
      --composer feedbuilder/output/composer_osv.json feedbuilder/output/composer_foph.json \
      [--wp feedbuilder/output/wp_nvd.json] \
      --out src/phpwarden/data/php-cve-feed.json \
      --feed-version 2026.10.23.1
"""
import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from phpwarden import version as V          # noqa: E402
from phpwarden.deps import _TOKEN, constraint_matches   # noqa: E402

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
_WILD = re.compile(r"^(\d+(?:\.\d+)*)\.(?:\*|x|X)$")

STATS = {"groups_dropped": 0, "advisories_dropped": 0, "fixed_removed": 0,
         "composer_merged": 0, "wp_merged": 0}


def _group_valid(group: str) -> bool:
    """Every comparator in the AND-group must be something the matcher parses."""
    toks = [m for m in _TOKEN.finditer(group) if m.group(0).strip()]
    text = re.sub(r"[\s,]", "", group)
    if not toks or "".join(m.group(0).replace(" ", "") for m in toks) != text:
        return False
    for m in toks:
        rhs = m.group(2)
        if rhs in ("*", "x", "X") or _WILD.match(rhs):
            continue
        if V.parse_loose(rhs) is None:
            return False
    return True


def _norm_affected(affected: str) -> str:
    groups = []
    for g in re.split(r"\|\|?", affected or ""):
        g = g.strip()
        if not g:
            continue
        if not _group_valid(g):
            STATS["groups_dropped"] += 1
            continue
        if g not in groups:
            groups.append(g)
    return "|".join(groups)


def _union_affected(a, b):
    return _norm_affected("|".join(x for x in (a or "", b or "") if x))


def _clean_fixed(affected: str, fixed) -> list:
    """Keep only fix versions that are outside the affected range."""
    out = []
    for f in fixed or []:
        f = str(f).strip()
        if not f or f in out or V.parse_loose(f) is None:
            continue
        if affected and constraint_matches(f, affected):
            STATS["fixed_removed"] += 1
            continue
        out.append(f)
    return out


def _merge_into(cur: dict, new: dict):
    cur["affected"] = _union_affected(cur.get("affected"), new.get("affected"))
    cur["fixed"] = list(cur.get("fixed", [])) + [f for f in new.get("fixed", [])
                                                 if f not in cur.get("fixed", [])]
    if _SEV_RANK.get(cur.get("severity", "unknown"), 0) == 0 and \
            _SEV_RANK.get(new.get("severity", "unknown"), 0) > 0:
        cur["severity"] = new["severity"]
    cur["cvss"] = max(float(cur.get("cvss") or 0), float(new.get("cvss") or 0))
    cur["known_exploited"] = bool(cur.get("known_exploited")) or bool(new.get("known_exploited"))
    if cur.get("ransomware") or new.get("ransomware"):
        cur["ransomware"] = True
    for k in ("epss", "epss_percentile"):
        if new.get(k) is not None:
            cur[k] = max(float(cur.get(k) or 0), float(new[k]))
    if not cur.get("title") and new.get("title"):
        cur["title"] = new["title"]
    refs = list(cur.get("references", []))
    for r in new.get("references", []):
        if r not in refs and len(refs) < 5:
            refs.append(r)
    cur["references"] = refs
    # dates: earliest publication, latest modification (ISO dates sort as text)
    if new.get("published") and (not cur.get("published") or new["published"] < cur["published"]):
        cur["published"] = new["published"]
    if new.get("modified") and (not cur.get("modified") or new["modified"] > cur["modified"]):
        cur["modified"] = new["modified"]
    cwes = list(cur.get("cwe", []))
    for c in new.get("cwe", []) or []:
        if c not in cwes and len(cwes) < 4:
            cwes.append(c)
    if cwes:
        cur["cwe"] = cwes


def _finalise(adv: dict) -> bool:
    """Normalise ranges and fixed; False if nothing matchable is left."""
    adv["affected"] = _norm_affected(adv.get("affected", ""))
    if not adv["affected"]:
        STATS["advisories_dropped"] += 1
        return False
    adv["fixed"] = _clean_fixed(adv["affected"], adv.get("fixed", []))
    return True


def merge_composer(base, imported):
    """Merge by (package, cve); first (curated) entry's metadata wins, see module doc."""
    out = list(base)
    index = {(a["package"], a.get("cve")): a for a in out}
    added = 0
    for a in imported:
        key = (a["package"], a.get("cve"))
        cur = index.get(key)
        if cur is None:
            index[key] = a
            out.append(a)
            added += 1
        else:
            _merge_into(cur, a)
            STATS["composer_merged"] += 1
    return out, added


def _slug_key(slug: str) -> str:
    return slug.strip().lower().replace("_", "-")


def merge_wp(base, imported):
    out = list(base)
    index = {(_slug_key(a["slug"]), a.get("cve")): a for a in out}
    added = 0
    for a in imported or []:
        key = (_slug_key(a["slug"]), a.get("cve"))
        cur = index.get(key)
        if cur is None:
            index[key] = a
            out.append(a)
            added += 1
        else:
            _merge_into(cur, a)
            STATS["wp_merged"] += 1
    return out, added


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--composer", nargs="*", default=[],
                    help="one or more composer advisory JSON files, merged in order")
    ap.add_argument("--wp")
    ap.add_argument("--out", required=True)
    ap.add_argument("--feed-version", required=True)
    ap.add_argument("--channel", default="community+foph")
    a = ap.parse_args()

    base = json.loads(Path(a.base).read_text())
    wp = json.loads(Path(a.wp).read_text()) if a.wp else []

    merged_comp = list(base.get("composer_advisories", []))
    added_c = 0
    for src in a.composer:
        imported = json.loads(Path(src).read_text())
        merged_comp, n = merge_composer(merged_comp, imported)
        added_c += n
    merged_wp, added_w = merge_wp(base.get("wp_advisories", []), wp)
    merged_comp = [x for x in merged_comp if _finalise(x)]
    merged_wp = [x for x in merged_wp if _finalise(x)]

    feed = {
        "feed_version": a.feed_version,
        "schema": base.get("schema", 1),
        "channel": a.channel,
        "generated": dt.date.today().isoformat(),
        "source": "curated base + OSV.dev + FriendsOfPHP/security-advisories"
                  + (" + NVD (WordPress)" if wp else ""),
        "cves": base.get("cves", []),
        "composer_advisories": merged_comp,
        "wp_advisories": merged_wp,
    }
    Path(a.out).write_text(json.dumps(feed, indent=1))
    kinds = {}
    for w in merged_wp:
        kinds[w.get("type", "plugin")] = kinds.get(w.get("type", "plugin"), 0) + 1
    print(f"wrote {a.out}: feed {a.feed_version}")
    print(f"  engine CVEs: {len(feed['cves'])}")
    print(f"  composer:    {len(merged_comp)} (+{added_c} imported, "
          f"{STATS['composer_merged']} merged into existing (package, cve))")
    print(f"  wordpress:   {len(merged_wp)} (+{added_w} imported, "
          f"{STATS['wp_merged']} merged into existing (slug, cve)) kinds={kinds}")
    print(f"  cleaned: {STATS['fixed_removed']} fixed versions inside affected ranges removed, "
          f"{STATS['groups_dropped']} unparseable OR-groups dropped, "
          f"{STATS['advisories_dropped']} advisories left with no range dropped")
    print(f"  size: {Path(a.out).stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
