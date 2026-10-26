#!/usr/bin/env python3
"""Import OSV.dev Packagist advisories into phpwarden composer entries.

OSV.dev is open vulnerability data (OpenSSF), aggregated from many upstreams and
built for programmatic reuse and redistribution. Importing it makes phpwarden's
Composer coverage independent of any single vendor's licensed database.

Source: https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip
(one JSON file per advisory, OSV schema 1.x). Stdlib only.

Range semantics (OSV spec): events are walked in order; `introduced` opens a
group, `fixed` closes it with "<fixed" (and records a fix), `last_affected`
closes it with "<=last" (no fix is known). An `introduced: 0` with no closing
event means every version is affected ("*"). Affected entries that carry only
an explicit `versions` list become exact-version groups. A group is never
emitted with only a lower bound unless the source really has no upper event,
in which case `fixed` is empty so the UI can say "no fix yet".

Severity: the CVSS v3 base score is computed from the record's vector
(cvss.py); v4-only records fall back to the source's severity label.

Usage:
  python3 -I import_osv.py <dir-of-osv-json> <out.json>
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # -I (-P) drops the script dir
import cvss   # noqa: E402


def _cve_id(doc):
    for a in doc.get("aliases", []) or []:
        if str(a).startswith("CVE-"):
            return a
    return doc.get("id")


def _ver(v):
    return str(v).strip().lstrip("vV")


def _affected_for(entry):
    """Return (constraint_groups, fixed[]) for one 'affected' entry."""
    ds = (entry.get("database_specific") or {})
    constraint = ds.get("affected_versions")
    fixed, groups = [], []
    for rng in entry.get("ranges", []) or []:
        rds = (rng.get("database_specific") or {})
        c = rds.get("constraint")
        if c:
            groups.append(c)
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    fixed.append(_ver(ev["fixed"]))
            continue
        intro = None
        opened = False
        for ev in rng.get("events", []) or []:
            if "introduced" in ev:
                if opened:   # a second introduced without a closing event
                    groups.append(_open_group(intro))
                intro, opened = _ver(ev["introduced"]), True
            elif "fixed" in ev and opened:
                fx = _ver(ev["fixed"])
                fixed.append(fx)
                groups.append(_closed_group(intro, "<" + fx))
                opened = False
            elif "last_affected" in ev and opened:
                groups.append(_closed_group(intro, "<=" + _ver(ev["last_affected"])))
                opened = False
        if opened:
            groups.append(_open_group(intro))
    if not groups and entry.get("versions"):
        groups = ["=" + _ver(v) for v in entry["versions"] if _ver(v)]
    if not groups and constraint:
        groups.append(constraint)
    return [g for g in groups if g], fixed


def _closed_group(intro, upper):
    if intro and intro != "0":
        return ">=" + intro + "," + upper
    return upper


def _open_group(intro):
    """No closing event: everything from `intro` on is affected (no fix known)."""
    if intro and intro != "0":
        return ">=" + intro
    return "*"


def convert(doc):
    if doc.get("withdrawn"):
        return []
    cve = _cve_id(doc)
    title = (doc.get("summary") or (doc.get("details") or "")[:120] or "").strip()
    refs = [r["url"] for r in (doc.get("references") or []) if r.get("url")][:3]
    score, severity = cvss.derive(doc.get("severity"),
                                  (doc.get("database_specific") or {}).get("severity"))
    out = []
    for entry in doc.get("affected", []) or []:
        pkg = (entry.get("package") or {})
        eco = pkg.get("ecosystem", "")
        name = pkg.get("name")
        if not name or not eco.startswith("Packagist"):
            continue
        groups, fixed = _affected_for(entry)
        if not groups:
            continue
        seen, fixed_u = set(), []
        for f in fixed:
            if f not in seen:
                seen.add(f); fixed_u.append(f)
        out.append({
            "package": name.lower(),
            "cve": cve,
            "title": title,
            "cvss": score,
            "severity": severity,
            "affected": "|".join(groups),
            "fixed": fixed_u,
            "known_exploited": False,
            "references": refs,
            "source": "osv.dev",
        })
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__); return 2
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    advisories, files = [], 0
    for jf in sorted(src.glob("*.json")):
        files += 1
        try:
            doc = json.loads(jf.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        advisories.extend(convert(doc))
    out.write_text(json.dumps(advisories, indent=1))
    pkgs = len({a["package"] for a in advisories})
    unknown = sum(1 for a in advisories if a["severity"] == "unknown")
    print(f"imported {len(advisories)} advisories across {pkgs} packages "
          f"from {files} OSV records -> {out}")
    print(f"  severity unknown: {unknown} (no CVSS v3 vector and no severity label)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
