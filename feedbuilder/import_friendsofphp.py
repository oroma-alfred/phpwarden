#!/usr/bin/env python3
"""Import FriendsOfPHP/security-advisories YAML into phpwarden composer entries.

This is BUILD tooling, not shipped runtime. It may use PyYAML (the source is
YAML); the runtime feed it produces stays pure JSON / stdlib.

Usage:
  python3 -I import_friendsofphp.py <extracted-repo-dir> <out.json>

The FriendsOfPHP advisory shape:
  title, link, cve (or ~), reference: composer://vendor/pkg,
  branches: { "<name>": { time: <fix release time or ~>, versions: ['>=a', '<b'] }, ... }

Mapped to a phpwarden composer advisory:
  package, cve/id, title, affected ("grp|grp" of comma-AND comparators),
  fixed, references, severity/cvss left unknown (FriendsOfPHP carries no
  CVSS; enrichment is a separate step).

"fixed" semantics: a branch's strict upper bound ("<2.7.49") is the release
that fixed it ONLY when the branch records a fix `time`. A branch with
`time: ~` and a bound like "<2.3.0" is an unfixed branch whose range simply
ends where the next branch starts — that bound is not a fix (2.3.0 is itself
affected in the next branch). When an advisory records no times at all we
cannot tell and fall back to every strict bound; build_feed.py then removes
any "fixed" version that still falls inside the affected ranges. "<=x"
bounds are "last affected", never a fix.
"""
import json
import re
import sys
from pathlib import Path

import yaml   # build-time dependency only

_STRICT_UPPER = re.compile(r"^<\s*([0-9][0-9A-Za-z.\-]*)$")


def convert(doc: dict, fallback_id: str):
    ref = (doc.get("reference") or "")
    if not ref.startswith("composer://"):
        return None
    package = ref[len("composer://"):].strip()
    branches = doc.get("branches") or {}
    any_timed = any(b.get("time") for b in branches.values() if isinstance(b, dict))
    groups, fixed = [], []
    for _name, b in branches.items():
        if not isinstance(b, dict):
            continue
        versions = [str(v).strip() for v in (b.get("versions") or []) if str(v).strip()]
        if not versions:
            continue
        groups.append(",".join(versions))
        if any_timed and not b.get("time"):
            continue                     # unfixed branch: its bound is not a fix
        for v in versions:
            m = _STRICT_UPPER.match(v.replace(" ", ""))
            if m:
                fixed.append(m.group(1))
    if not groups:
        return None
    cve = doc.get("cve")
    ident = cve if cve and cve != "~" else fallback_id
    # dedup fixed, keep order
    seen, fixed_u = set(), []
    for f in fixed:
        if f not in seen:
            seen.add(f); fixed_u.append(f)
    return {
        "package": package.lower(),
        "cve": ident,
        "title": (doc.get("title") or "").strip(),
        "cvss": 0.0,
        "severity": "unknown",
        "affected": "|".join(groups),
        "fixed": fixed_u,
        "known_exploited": False,
        "references": [doc["link"]] if doc.get("link") else [],
        "source": "friendsofphp",
    }


def main():
    if len(sys.argv) != 3:
        print(__doc__); return 2
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    advisories, errors = [], 0
    for yml in sorted(src.rglob("*.yaml")):
        if "/." in str(yml):
            continue
        try:
            doc = yaml.safe_load(yml.read_text(errors="replace"))
        except Exception:  # noqa: BLE001
            errors += 1
            continue
        if not isinstance(doc, dict):
            continue
        adv = convert(doc, fallback_id=yml.stem)
        if adv:
            advisories.append(adv)
    out.write_text(json.dumps(advisories, indent=1))
    pkgs = len({a["package"] for a in advisories})
    print(f"imported {len(advisories)} advisories across {pkgs} packages "
          f"({errors} files skipped) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
