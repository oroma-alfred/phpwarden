"""One exploitability verdict per issue, from every angle phpwarden can see.

`phpwarden assess` combines four independent views of the same site:

  installed   composer.lock and the WordPress install on disk      (deps, wordpress)
  code        your own PHP code                                    (code)
  outside     what the live site shows to anyone on the internet   (probe)
  attacked    what is already arriving in the access log           (detect)

and turns them into one ranked list where every item says *why* it is where it
is. The question it answers is not "how severe is this CVE" but "is this one
being used against sites like mine, is it actually reachable here, can it be
seen from outside, and is someone already trying it".

Tiers (highest first):

  act-now     exploited in the wild (CISA KEV / EPSS >= 50%) or already being
              attacked here, AND present in a way that is reachable; or a
              secret-bearing file is downloadable from outside.
  this-week   critical/high and reachable; exploited-in-the-wild issues that
              look unreachable here (dev-only / unreferenced), with that caveat
              stated; critical/high findings in your own code or from outside.
  scheduled   medium, or high but unreachable.
  watch       low / informational.

Nothing here is a guess presented as fact: each signal is either observed
("seen") or explicitly absent ("not checked" when that view was not supplied,
"not seen" when it was supplied and found nothing). Stdlib only.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from phpwarden import __version__

TIERS = ["act-now", "this-week", "scheduled", "watch"]
_TIER_RANK = {t: i for i, t in enumerate(TIERS)}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 3}
EPSS_HOT = 0.5
# probe findings where a secret or the source tree itself is downloadable
_SECRET_EXPOSURES = ("exposed-env", "exposed-git", "exposed-wpconfig", "exposed-backup", "exposed-database")


def _hot(known_exploited, epss) -> bool:
    return bool(known_exploited) or (isinstance(epss, (int, float)) and epss >= EPSS_HOT)


def _pct(epss) -> str:
    return f"{epss * 100:.0f}%" if isinstance(epss, (int, float)) else "n/a"


# --------------------------------------------------------------------------- #
# Collecting each view
# --------------------------------------------------------------------------- #
def _collect_deps(root: Path, feed):
    """[(key, item)] for vulnerable Composer packages, with reachability."""
    from phpwarden.deps import analyze_reachability, scan_lock
    lock = root / "composer.lock"
    if not lock.is_file():
        return None
    try:
        findings = scan_lock(str(lock), feed)
    except Exception:  # noqa: BLE001 — a broken lockfile means "view unavailable"
        return None
    try:
        reach = analyze_reachability(str(lock), str(root))
    except Exception:  # noqa: BLE001
        reach = {}
    out = []
    for f in findings:
        a = f.advisory
        out.append({"kind": "dependency", "component": f.package, "version": f.installed,
                    "cve": a.cve or "", "title": a.title, "severity": a.severity or "unknown",
                    "cvss": a.cvss, "known_exploited": bool(a.known_exploited), "epss": a.epss,
                    "ransomware": bool(getattr(a, "ransomware", False)),
                    "fixed": list(f.fixed), "reach": reach.get(f.package, "unknown")})
    return out


def _collect_wordpress(root: Path, feed):
    from phpwarden import wordpress as wp
    if not (root / "wp-includes").is_dir():
        return None
    out = []
    for f in wp.scan(str(root), feed):
        a, c = f.advisory, f.component
        out.append({"kind": "wordpress", "component": f"{c.kind} {c.slug}" if c.kind != "core" else "WordPress core",
                    "slug": c.slug, "wp_kind": c.kind, "version": c.version,
                    "cve": a.cve or "", "title": a.title, "severity": a.severity or "unknown",
                    "cvss": a.cvss, "known_exploited": bool(a.known_exploited), "epss": a.epss,
                    "ransomware": bool(getattr(a, "ransomware", False)),
                    "fixed": list(f.fixed), "reach": "used"})   # an installed plugin is loaded code
    return out


def _collect_code(root: Path, dep_items):
    from phpwarden import code as codescan
    lock_findings = [{"package": d["component"], "cve": d["cve"], "known_exploited": d["known_exploited"]}
                     for d in (dep_items or [])]
    try:
        return codescan.scan_project(str(root), lock_findings=lock_findings or None)
    except Exception:  # noqa: BLE001
        return None


def _log_view(logfile, feed):
    """Signature hits per CVE plus every request path with its 2xx count, so
    probe exposures can be checked against "was this file already fetched"."""
    from phpwarden.detect import SignatureScanner, parse_access_line
    scanner = SignatureScanner(feed)
    by_cve, sample = Counter(), {}
    path_ok, path_ips, lines = Counter(), {}, 0
    with open(logfile, "r", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            lines = n
            for h in scanner.scan_line(line, "access", n):
                by_cve[h.cve_id] += 1
                sample.setdefault(h.cve_id, {"line": n, "excerpt": h.excerpt[:200]})
            rec = parse_access_line(line)
            if not rec:
                continue
            req = rec.get("req", "")
            parts = req.split(" ")
            if len(parts) < 2:
                continue
            path = parts[1].split("?")[0]
            if str(rec.get("status", ""))[:1] == "2":
                path_ok[path] += 1
                path_ips.setdefault(path, set()).add(rec.get("ip", ""))
    return {"lines": lines, "by_cve": dict(by_cve), "sample": sample,
            "path_ok": path_ok, "path_ips": path_ips}


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #
def _tier_for_vuln(it, attacked: bool, live: Optional[bool]) -> str:
    hot = _hot(it["known_exploited"], it.get("epss"))
    reach = it.get("reach", "unknown")
    reachable = reach in ("used", "unknown")
    sev = _SEV_RANK.get(it["severity"], 3)
    if (hot or attacked) and (reachable or live):
        return "act-now"
    if hot:                                   # exploited elsewhere, looks unreachable here
        return "this-week"
    if sev <= 1:
        return "this-week" if (reachable or live) else "scheduled"
    if sev == 2:
        return "scheduled"
    return "watch"


def _why_vuln(it, attack, live, views) -> list:
    why = [f"installed: {it['component']} {it['version']}"]
    if it["known_exploited"]:
        why.append("exploited in the wild: on CISA's Known Exploited Vulnerabilities list"
                   + (" (used in ransomware campaigns)" if it.get("ransomware") else ""))
    elif isinstance(it.get("epss"), (int, float)) and it["epss"] >= EPSS_HOT:
        why.append(f"likely to be exploited: EPSS {_pct(it['epss'])}")
    if it["kind"] == "dependency":
        r = it["reach"]
        why.append({"used": "reachable: your code references this package",
                    "unreferenced": "not referenced by your code (installed but unused)",
                    "dev-only": "dev dependency only: not loaded in production",
                    "unknown": "reachability unknown: no project source to check against"}[r])
    if live is True:
        why.append("visible from outside: the live site reports this vulnerable version")
    elif live is False and "outside" in views and it["kind"] == "wordpress":
        # only said for WordPress: a Composer package's version is never visible
        # from outside, so "not confirmed" there would mean nothing
        why.append("not confirmed from outside: the live site does not reveal this version")
    if attack:
        why.append(f"being attacked: {attack['requests']} request(s) in the access log match this "
                   f"vulnerability's exploit signature (e.g. line {attack['sample_line']})")
    elif "attacked" in views and it.get("cve") in views["attacked_cves_with_sigs"]:
        why.append("no exploit attempts for it in the access log")
    return why


def assess(path=None, *, feed=None, probe_result=None, logfile=None, run_code=True) -> dict:
    """Build the combined verdict.

    path          project / site root (composer.lock, WordPress, PHP code); optional
    probe_result  a dict from probe.run_probe (the outside view); optional
    logfile       an access log (the attacked view); optional
    """
    if feed is None:
        from phpwarden.feed import FeedManager
        feed = FeedManager().current()
    root = Path(path) if path else None
    views = {}
    deps = wpf = code_res = None
    if root is not None and root.is_dir():
        deps = _collect_deps(root, feed)
        wpf = _collect_wordpress(root, feed)
        if deps is not None or wpf is not None:
            views["installed"] = {"composer": deps is not None, "wordpress": wpf is not None}
        if run_code:
            code_res = _collect_code(root, deps)
            if code_res is not None:
                views["code"] = {"files_scanned": code_res.get("files_scanned", 0)}
    log = None
    if logfile:
        log = _log_view(logfile, feed)
        views["attacked"] = {"log_lines": log["lines"]}
    views["attacked_cves_with_sigs"] = set()
    if log is not None:
        from phpwarden.detect import SignatureScanner
        views["attacked_cves_with_sigs"] = {s[0] for s in SignatureScanner(feed).sigs}
    live_cves, probe_other = {}, []
    if probe_result:
        views["outside"] = {"mode": probe_result.get("mode"), "target": probe_result.get("target"),
                            "verified": bool((probe_result.get("ownership") or {}).get("verified"))}
        for f in probe_result.get("findings", []):
            if f.get("kind") == "vuln" and f.get("cve"):
                live_cves.setdefault(f["cve"], f)
            else:
                probe_other.append(f)

    items = []

    def attack_for(cve):
        if log is None or not cve or cve not in log["by_cve"]:
            return None
        return {"requests": log["by_cve"][cve], "sample_line": log["sample"][cve]["line"],
                "sample": log["sample"][cve]["excerpt"]}

    seen_cves = set()
    for it in (deps or []) + (wpf or []):
        cve = it["cve"]
        attack = attack_for(cve)
        live = (cve in live_cves) if "outside" in views else None
        tier = _tier_for_vuln(it, bool(attack), live)
        seen_cves.add(cve)
        items.append({
            "id": f"{it['kind']}:{it['component']}:{cve or it['title'][:40]}",
            "tier": tier, "kind": it["kind"], "component": it["component"], "version": it["version"],
            "cve": cve or None, "title": it["title"], "severity": it["severity"],
            "signals": {"installed": True, "known_exploited": it["known_exploited"], "epss": it.get("epss"),
                        "reach": it.get("reach") if it["kind"] == "dependency" else None,
                        "visible_from_outside": live, "attacked": attack},
            "why": _why_vuln(it, attack, live, views),
            "fix": ("Upgrade to " + " / ".join(it["fixed"][:4])) if it["fixed"] else "No fixed version published; remove or isolate it.",
        })

    # Vulnerabilities only the outside view saw (no path given, or not on disk).
    for cve, f in live_cves.items():
        if cve in seen_cves:
            continue
        attack = attack_for(cve)
        hot = _hot(f.get("known_exploited"), f.get("epss"))
        sev = _SEV_RANK.get(f.get("severity"), 3)
        possibly = "(possibly)" in (f.get("title") or "")
        tier = ("act-now" if (hot or attack) and not possibly else
                "this-week" if hot or sev <= 1 else "scheduled" if sev == 2 else "watch")
        why = ["visible from outside: " + (f.get("evidence") or "the live site reports this version")]
        if possibly:
            why.append("not certain: the server's setup (SAPI/OS) cannot be seen from outside")
        if f.get("known_exploited"):
            why.append("exploited in the wild: on CISA's Known Exploited Vulnerabilities list")
        if attack:
            why.append(f"being attacked: {attack['requests']} matching request(s) in the access log")
        items.append({"id": f"outside:{f['id']}", "tier": tier, "kind": "outside-vuln",
                      "component": (f.get("title") or "").split(":")[0], "version": None, "cve": cve,
                      "title": f.get("title"), "severity": f.get("severity"),
                      "signals": {"installed": None, "known_exploited": bool(f.get("known_exploited")),
                                  "epss": f.get("epss"), "reach": None, "visible_from_outside": True,
                                  "attacked": attack},
                      "why": why, "fix": f.get("fix") or "Upgrade to a fixed release."})

    # Exposures, endpoints, headers from the outside view.
    for f in probe_other:
        sev = f.get("severity", "low")
        fetched = None
        if log is not None and f.get("url"):
            p = urlsplit(f["url"]).path or "/"
            if p != "/" and log["path_ok"].get(p):
                ips = {i for i in log["path_ips"].get(p, ()) if i}
                fetched = {"requests": log["path_ok"][p], "clients": len(ips)}
        secret = any(str(f.get("id", "")).startswith(s) for s in _SECRET_EXPOSURES)
        tier = ("act-now" if sev == "critical" or (fetched and sev in ("critical", "high")) or _hot(f.get("known_exploited"), f.get("epss"))
                else "this-week" if sev == "high" else "scheduled" if sev == "medium" else "watch")
        why = [f"visible from outside: {f.get('evidence') or f.get('title')}"]
        if fetched:
            why.append(f"already fetched: the access log shows {fetched['requests']} successful request(s) "
                       f"for this path from {fetched['clients']} client address(es)"
                       + ("; treat every secret in it as leaked and rotate it" if secret else ""))
        elif log is not None and f.get("kind") in ("exposure", "endpoint"):
            why.append("no successful requests for this path in the access log supplied")
        if f.get("known_exploited"):
            why.append("exploited in the wild: on CISA's Known Exploited Vulnerabilities list")
        items.append({"id": f"outside:{f['id']}", "tier": tier, "kind": f"outside-{f.get('kind')}",
                      "component": urlsplit(f.get("url") or "").path or "site", "version": None,
                      "cve": f.get("cve"), "title": f.get("title"), "severity": sev,
                      "signals": {"installed": None, "known_exploited": bool(f.get("known_exploited")),
                                  "epss": f.get("epss"), "reach": None, "visible_from_outside": True,
                                  "attacked": None, "already_fetched": fetched},
                      "why": why, "fix": f.get("fix") or ""})

    # Findings in the site's own code.
    for f in (code_res or {}).get("findings", []):
        sev = f["severity"]
        tier = "this-week" if sev in ("critical", "high") else "scheduled" if sev == "medium" else "watch"
        why = [f"in your code: {f['file']}:{f['line']}"]
        for c in f.get("context") or []:
            if c.startswith("gadget-chain"):
                why.append("made worse by an installed package with a known deserialization gadget chain ("
                           + c.split(":", 1)[1].strip() + ")")
            elif c.startswith("known-exploited"):
                why.append("an installed dependency it can reach is exploited in the wild ("
                           + c.split(":", 1)[1].strip() + ")")
                if sev in ("critical", "high"):
                    tier = "act-now"
        items.append({"id": f"code:{f['rule']}:{f['file']}:{f['line']}", "tier": tier, "kind": "code",
                      "component": f["file"], "version": None, "cve": None, "title": f["title"],
                      "severity": sev,
                      "signals": {"installed": None, "known_exploited": False, "epss": None, "reach": "used",
                                  "visible_from_outside": None, "attacked": None},
                      "why": why, "fix": f.get("fix") or "", "line": f["line"], "rule": f["rule"]})

    # Attacks against CVEs that are NOT present: worth one line, not an alarm.
    noise = []
    if log is not None:
        for cve, n in sorted(log["by_cve"].items(), key=lambda kv: -kv[1]):
            if cve not in seen_cves and cve not in live_cves:
                noise.append({"cve": cve, "requests": n})

    items.sort(key=lambda i: (
        _TIER_RANK[i["tier"]],
        0 if i["signals"].get("attacked") or i["signals"].get("already_fetched") else 1,
        0 if i["signals"]["known_exploited"] else 1,
        -(i["signals"].get("epss") or 0),
        _SEV_RANK.get(i["severity"], 3), i["id"]))
    summary = {t: sum(1 for i in items if i["tier"] == t) for t in TIERS}
    summary["total"] = len(items)
    views.pop("attacked_cves_with_sigs", None)
    for name in ("installed", "code", "outside", "attacked"):
        views.setdefault(name, None)            # None = this view was not supplied
    return {"tool": "phpwarden-assess", "version": __version__,
            "feed_version": getattr(feed, "feed_version", None),
            "target": str(root) if root else (probe_result or {}).get("target"),
            "views": views, "summary": summary, "items": items,
            "attack_noise": noise}


# --------------------------------------------------------------------------- #
# Proof of fix
# --------------------------------------------------------------------------- #
_VIEW_OF = {"dependency": "installed", "wordpress": "installed", "code": "code"}


def _view_of(item) -> str:
    return _VIEW_OF.get(item["kind"], "outside")


def compare(before: dict, after: dict) -> dict:
    """What changed between two assessments of the same site.

    An item counts as **fixed and verified** only when the view that reported it
    ran again in `after` and no longer reports it. If that view is missing from
    `after` (no probe this time, say), the item is "not re-checked", never
    "fixed". For outside findings that needed active checks, `after` must have
    been an active (ownership-verified) probe too."""
    b = {i["id"]: i for i in before.get("items", [])}
    a = {i["id"]: i for i in after.get("items", [])}
    av = after.get("views") or {}
    fixed, unverified, still, new = [], [], [], []
    for iid, it in b.items():
        if iid in a:
            still.append(a[iid])
            continue
        view = _view_of(it)
        ran = av.get(view) is not None
        if view == "outside" and ran and it["kind"] in ("outside-exposure", "outside-endpoint"):
            ran = (av["outside"] or {}).get("mode") == "active"
        if view == "installed" and ran:
            sub = "composer" if it["kind"] == "dependency" else "wordpress"
            ran = bool((av["installed"] or {}).get(sub))
        (fixed if ran else unverified).append(it)
    for iid, it in a.items():
        if iid not in b:
            new.append(it)
    how = {"installed": "the installed version is no longer in the affected range",
           "code": "the code scanner no longer finds it",
           "outside": "re-checked from outside: no longer visible on the live site"}
    return {
        "fixed": [{"id": i["id"], "title": i["title"], "cve": i.get("cve"), "was_tier": i["tier"],
                   "verified_by": how[_view_of(i)]} for i in fixed],
        "not_rechecked": [{"id": i["id"], "title": i["title"], "cve": i.get("cve"),
                           "reason": f"the {_view_of(i)} view was not run this time"} for i in unverified],
        "still_open": [{"id": i["id"], "title": i["title"], "cve": i.get("cve"), "tier": i["tier"]} for i in still],
        "new": [{"id": i["id"], "title": i["title"], "cve": i.get("cve"), "tier": i["tier"]} for i in new],
        "before_feed": before.get("feed_version"), "after_feed": after.get("feed_version"),
    }


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
_LABEL = {"act-now": "ACT NOW", "this-week": "THIS WEEK", "scheduled": "SCHEDULED", "watch": "WATCH"}


def to_text(res: dict, diff: dict = None, max_watch: int = 5) -> str:
    v = res["views"]
    seen = [n for n in ("installed", "code", "outside", "attacked") if v.get(n) is not None]
    missing = [n for n in ("installed", "code", "outside", "attacked") if v.get(n) is None]
    s = res["summary"]
    out = [f"phpwarden assess {res['version']}  target={res['target']}  feed={res['feed_version']}",
           f"  views used: {', '.join(seen) or 'none'}"
           + (f"   (not checked: {', '.join(missing)})" if missing else ""),
           f"  {s['act-now']} act now, {s['this-week']} this week, {s['scheduled']} scheduled, {s['watch']} watch"]
    if diff is not None:
        out.append("")
        out.append(f"Since the baseline: {len(diff['fixed'])} fixed and verified, {len(diff['still_open'])} still open, "
                   f"{len(diff['new'])} new" + (f", {len(diff['not_rechecked'])} not re-checked" if diff["not_rechecked"] else ""))
        for f in diff["fixed"]:
            out.append(f"  FIXED  {f['cve'] or ''} {f['title'][:90]}".rstrip())
            out.append(f"         {f['verified_by']}")
        for f in diff["not_rechecked"]:
            out.append(f"  ?      {f['cve'] or ''} {f['title'][:80]} — {f['reason']}")
    shown_watch = 0
    last = None
    for it in res["items"]:
        if it["tier"] == "watch":
            shown_watch += 1
            if shown_watch > max_watch:
                continue
        if it["tier"] != last:
            out.append("")
            out.append(f"{_LABEL[it['tier']]}")
            last = it["tier"]
        head = f"  {it['component']}" + (f" {it['version']}" if it.get("version") else "")
        out.append(f"{head}  {it.get('cve') or ''}  [{it['severity']}]".rstrip())
        out.append(f"      {(it['title'] or '')[:150]}")
        for w in it["why"]:
            out.append(f"      - {w}")
        if it.get("fix"):
            out.append(f"      fix: {it['fix']}")
    if shown_watch > max_watch:
        out.append(f"  ... and {shown_watch - max_watch} more low-priority item(s); use --json for all")
    if not res["items"]:
        out.append("")
        out.append("Nothing found in the views that were checked.")
    if res.get("attack_noise"):
        n = res["attack_noise"]
        out.append("")
        out.append("Exploit attempts in the log for vulnerabilities you do NOT have (no action needed): "
                   + ", ".join(f"{x['cve']} ({x['requests']})" for x in n[:6]))
    return "\n".join(out)


def exit_code(res: dict) -> int:
    """1 when anything needs action now or this week, else 0."""
    return 1 if res["summary"]["act-now"] or res["summary"]["this-week"] else 0


def load(path) -> dict:
    return json.loads(Path(path).read_text())
