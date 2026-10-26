#!/usr/bin/env python3
"""Import a Wordfence-Intelligence-shaped vulnerability feed into wp_advisories.

Build tooling (stdlib only). The Wordfence Intelligence "production" feed is a
JSON object keyed by vulnerability id; each entry lists affected software with
version ranges. This maps that schema into phpwarden WordPress advisories.

The live bulk feed now requires a (free) registered Wordfence Intelligence key,
or use Patchstack's API — either populates the maintained subscription channel.
This importer takes the already-downloaded JSON so it works offline too.

Usage:
  python3 -I import_wordfence.py <wordfence.json> <out.json>
"""
import json
import sys
from pathlib import Path


def _range_to_constraint(r: dict):
    """One affected_versions range -> ('>=a,<b' style group, fixed_version|None)."""
    parts, fixed = [], None
    frm = r.get("from_version")
    if frm and frm != "*":
        parts.append((">=" if r.get("from_inclusive", True) else ">") + frm)
    to = r.get("to_version")
    if to and to != "*":
        if r.get("to_inclusive", False):
            parts.append("<=" + to)
        else:
            parts.append("<" + to)
            fixed = to            # first safe version is the exclusive upper bound
    return (",".join(parts) if parts else None), fixed


def convert(vid: str, entry: dict):
    out = []
    cve = entry.get("cve") or vid
    title = (entry.get("title") or "").strip()
    cvss = entry.get("cvss") or {}
    score = float(cvss.get("score", 0) or 0)
    rating = (cvss.get("rating") or "unknown").lower()
    refs = entry.get("references", []) or []
    for sw in entry.get("software", []) or []:
        if sw.get("type") not in ("plugin", "theme"):
            continue
        slug = sw.get("slug")
        if not slug:
            continue
        groups, fixes = [], []
        for _label, r in (sw.get("affected_versions") or {}).items():
            grp, fixed = _range_to_constraint(r)
            if grp:
                groups.append(grp)
            if fixed:
                fixes.append(fixed)
        if not groups:
            continue
        out.append({
            "slug": slug, "type": sw["type"], "cve": cve, "title": title,
            "cvss": score, "severity": rating, "affected": "|".join(groups),
            "fixed": sorted(set(fixes)),
            "known_exploited": bool(entry.get("cwe_known_exploited", False)),
            "references": refs[:3],
        })
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__); return 2
    doc = json.loads(Path(sys.argv[1]).read_text())
    entries = doc.values() if isinstance(doc, dict) else doc
    advisories = []
    for entry in entries:
        vid = entry.get("id", "")
        advisories.extend(convert(vid, entry))
    Path(sys.argv[2]).write_text(json.dumps(advisories, indent=1))
    slugs = len({a["slug"] for a in advisories})
    print(f"imported {len(advisories)} WordPress advisories across {slugs} slugs "
          f"-> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
