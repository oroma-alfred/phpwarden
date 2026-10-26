#!/usr/bin/env python3
"""Data-quality gate for a built feed (stdlib only; uses the runtime matcher).

    python3 -I check_feed.py <feed.json> [--verbose]

Exit 0 when every ERROR count is zero, 1 otherwise. Checks:

  ERROR open-with-fix     an OR-group with only a lower bound (">=2.16.0" and
                          nothing above) while one of the advisory's fixed
                          versions lies inside it — every later version would
                          be flagged, including the fix. An open group is
                          legitimate for a branch with no fix (reported as
                          INFO: either the whole advisory has "fixed": [] or
                          the fix belongs to another branch, e.g. 3.x fixed
                          while 4.x is still open).
  ERROR fixed-in-range    a "fixed" version that the affected range matches
  ERROR duplicate         same (package, cve) / (slug, cve) twice (slug "_"=="-")
  ERROR bad-version       a comparator the matcher cannot parse ("<=.51")
  ERROR slug-vs-cpe       an NVD WordPress advisory whose slug differs from its
                          CPE product without wordpress.org-reference or
                          curated backing (see import_nvd_wordpress.py)
  INFO  open-no-fix       open-ended groups on advisories with no fix (reported)
  INFO  severity          distribution per section, and known-exploited with
                          severity "unknown"
"""
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from phpwarden import version as V          # noqa: E402
from phpwarden.deps import _TOKEN, constraint_matches   # noqa: E402

_WILD = re.compile(r"^(\d+(?:\.\d+)*)\.(?:\*|x|X)$")


def groups_of(affected):
    return [g.strip() for g in re.split(r"\|\|?", affected or "") if g.strip()]


def comparators(group):
    return [(m.group(1) or "=", m.group(2)) for m in _TOKEN.finditer(group) if m.group(0).strip()]


def group_has_upper(group):
    for op, rhs in comparators(group):
        if rhs in ("*", "x", "X") or _WILD.match(rhs):
            return True
        if op in ("<", "<=", "=", "=="):
            return True
    return False


def group_bad_version(group):
    """True if the matcher would not read this AND-group the way it is written:
    tokens must cover the whole text (nothing like "<=.51" skipped) and every
    right-hand side must parse as a version."""
    comps = comparators(group)
    text = re.sub(r"[\s,]", "", group)
    covered = "".join(m.group(0).replace(" ", "") for m in _TOKEN.finditer(group))
    if not comps or covered != text:
        return True
    for op, rhs in comps:
        if rhs in ("*", "x", "X") or _WILD.match(rhs):
            continue
        if V.parse_loose(rhs) is None:
            return True
    return False


def _slug_key(s):
    return (s or "").strip().lower().replace("_", "-")


def main(argv):
    if len(argv) < 2:
        print(__doc__); return 2
    verbose = "--verbose" in argv
    feed = json.loads(Path(argv[1]).read_text())
    errors = collections.Counter()
    info = collections.Counter()
    detail = collections.defaultdict(list)

    for section, key in (("composer_advisories", "package"), ("wp_advisories", "slug")):
        items = feed.get(section, []) or []
        seen = collections.Counter()
        for a in items:
            ident = f"{a.get(key)} {a.get('cve')}"
            name = a.get(key, "")
            k = (_slug_key(name) if key == "slug" else name, a.get("cve"))
            seen[k] += 1
            gs = groups_of(a.get("affected", ""))
            fixed = a.get("fixed") or []
            open_groups = [g for g in gs if not group_has_upper(g)]
            if open_groups:
                # An open group is wrong when one of the advisory's own fixed
                # versions lies inside it (the range should have closed there).
                # A fix for another branch (3.x fixed, 4.x still open) is fine.
                inside = [f for f in fixed for g in open_groups
                          if V.parse_loose(f) is not None and constraint_matches(f, g)]
                if inside:
                    errors[f"{section}:open-with-fix"] += 1
                    detail["open-with-fix"].append(f"{ident} affected={a.get('affected')} fixed={fixed}")
                elif fixed:
                    info[f"{section}:open-branch-beside-fixed-branch"] += 1
                else:
                    info[f"{section}:open-no-fix"] += 1
            for g in gs:
                if group_bad_version(g):
                    errors[f"{section}:bad-version"] += 1
                    detail["bad-version"].append(f"{ident} group={g!r}")
            for f in fixed:
                if V.parse_loose(f) is None or constraint_matches(f, a.get("affected", "")):
                    errors[f"{section}:fixed-in-range"] += 1
                    detail["fixed-in-range"].append(f"{ident} fixed={f} affected={a.get('affected')}")
            info[f"{section}:severity={a.get('severity', 'unknown')}"] += 1
            if a.get("known_exploited") and a.get("severity", "unknown") == "unknown":
                info[f"{section}:kev-with-unknown-severity"] += 1
            if key == "slug":
                info[f"{section}:kind={a.get('type', 'plugin')}"] += 1
                cpe = a.get("cpe")
                if cpe and a.get("source") == "nvd":
                    product = cpe.split(":", 1)[1] if ":" in cpe else cpe
                    if a.get("type") == "core":
                        ok = a.get("slug") == "wordpress" and product == "wordpress"
                    else:
                        ok = _slug_key(a.get("slug")) == _slug_key(product) or \
                            a.get("slug_source") in ("wordpress.org", "curated")
                    if not ok:
                        errors[f"{section}:slug-vs-cpe"] += 1
                        detail["slug-vs-cpe"].append(f"{ident} cpe={cpe} slug_source={a.get('slug_source')}")
                    if a.get("slug_source"):
                        info[f"{section}:slug-from-{a['slug_source']}"] += 1
        for k, n in seen.items():
            if n > 1:
                errors[f"{section}:duplicate"] += 1
                detail["duplicate"].append(f"{k[0]} {k[1]} x{n}")

    print(f"feed {feed.get('feed_version')}  composer={len(feed.get('composer_advisories', []))} "
          f"wp={len(feed.get('wp_advisories', []))} cves={len(feed.get('cves', []))}")
    print("ERRORS:")
    for k in ("composer_advisories", "wp_advisories"):
        for chk in ("open-with-fix", "fixed-in-range", "duplicate", "bad-version", "slug-vs-cpe"):
            if chk == "slug-vs-cpe" and k != "wp_advisories":
                continue
            print(f"  {k}:{chk} = {errors.get(f'{k}:{chk}', 0)}")
    print("INFO:")
    for k in sorted(info):
        print(f"  {k} = {info[k]}")
    if verbose:
        for chk, rows in detail.items():
            print(f"--- {chk} ({len(rows)})")
            for r in rows[:200]:
                print("   ", r)
    total = sum(errors.values())
    print("RESULT:", "OK" if total == 0 else f"{total} ERRORS")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
