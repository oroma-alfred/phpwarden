"""Build a per-site shield policy: rules only for vulnerabilities this site has.

    policy = build_policy(inventory, feed)
    policy = build_policy_for_path("/var/www/site", feed)

inventory = {
    "composer":  {"vendor/package": "1.2.3", ...},
    "wordpress": {"core": "6.4.2", "plugins": {"slug": "1.0"}, "themes": {"slug": "2.0"}},
    "php":       {"version": "8.1.2", "sapi": "fpm"},          # sapi may be None
}

A library rule is included when (1) its component is installed, (2) the
installed version is inside the affected range the feed (or, failing that, the
library) gives for that CVE, and (3) the CVE is known exploited (CISA KEV) or
likely to be (EPSS >= 0.5). Upgrading the component past the fix drops the rule
on the next build. Generic rules are always included, except the serialized-
object rule, which needs a package with a known gadget chain.

Every rule starts in mode "log". promote() is the only way to "block", and it
refuses without an explicit operator acknowledgement and a clean burn-in.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from phpwarden import __version__
from phpwarden.shield.library import GADGET_PACKAGES, LIBRARY

EPSS_HOT = 0.5
BURN_IN_DAYS = 7
POLICY_VERSION = 1


def _norm(s):
    return (s or "").lower().replace("_", "-")


def _advisories(feed, cve, target):
    t = target["type"]
    if t == "composer":
        return [a for a in getattr(feed, "composer", []) if a.cve == cve and a.package == target["package"]]
    if t in ("wp-plugin", "wp-theme", "wp-core"):
        kind = {"wp-plugin": "plugin", "wp-theme": "theme", "wp-core": "core"}[t]
        slug = "wordpress" if t == "wp-core" else _norm(target["slug"])
        return [a for a in getattr(feed, "wp", []) if a.cve == cve and a.type == kind and _norm(a.slug) == slug]
    return []


def _installed(inventory, target):
    t = target["type"]
    if t == "composer":
        return (inventory.get("composer") or {}).get(target["package"])
    wp = inventory.get("wordpress") or {}
    if t == "wp-core":
        return wp.get("core")
    if t == "wp-plugin":
        return {_norm(k): v for k, v in (wp.get("plugins") or {}).items()}.get(_norm(target["slug"]))
    if t == "wp-theme":
        return {_norm(k): v for k, v in (wp.get("themes") or {}).items()}.get(_norm(target["slug"]))
    if t == "engine":
        return (inventory.get("php") or {}).get("version")
    return None


def _engine_status(feed, cve_id, php):
    """(present, exploited, why) for an engine CVE on this PHP."""
    from phpwarden import version as V
    from phpwarden.engine import Environment, assess_one
    cve = next((c for c in getattr(feed, "cves", []) if c.id == cve_id), None)
    if cve is None or not php.get("version"):
        return False, False, "no version or not in feed"
    env = Environment(version=V.parse(php["version"]), sapi=php.get("sapi"), os=php.get("os"))
    f = assess_one(cve, env)
    hot = bool(cve.exploited_in_wild) or (cve.epss or 0) >= EPSS_HOT
    return f.verdict in ("EXPOSED", "POSSIBLY_EXPOSED"), hot, f.verdict


def rule_status(entry, inventory, feed):
    """(include, reason) for one library entry on this site."""
    from phpwarden.deps import constraint_matches
    t = entry["target"]
    if t["type"] == "generic":
        if t.get("requires_gadget"):
            present = sorted(set(inventory.get("composer") or {}) & GADGET_PACKAGES)
            if (inventory.get("wordpress") or {}).get("core"):
                present.append("wordpress")
            return (bool(present), "gadget-chain package installed: " + ", ".join(present) if present
                    else "no package with a known gadget chain")
        return True, "generic exploit-in-progress check"
    if t["type"] == "engine":
        present, hot, why = _engine_status(feed, entry["cve"], inventory.get("php") or {})
        if not present:
            return False, f"PHP not affected ({why})"
        if t.get("sapi") and (inventory.get("php") or {}).get("sapi") not in (None, t["sapi"]):
            return False, f"only affects the {t['sapi']} SAPI"
        return (hot, "exploited in the wild" if hot else "not exploited or likely")
    ver = _installed(inventory, t)
    if not ver:
        return False, "component not installed"
    advs = _advisories(feed, entry["cve"], t)
    if advs:
        affected = [a for a in advs if a.affected and constraint_matches(ver, a.affected)]
        if not affected:
            return False, f"installed {ver} is not in the affected range (fixed)"
        hot = any(a.known_exploited or (a.epss or 0) >= EPSS_HOT for a in affected)
        return (hot, f"installed {ver} is affected; " + ("exploited in the wild" if any(a.known_exploited for a in affected)
                                                          else "EPSS >= 50%" if hot else "not exploited or likely"))
    if entry.get("affected"):
        if not constraint_matches(ver, entry["affected"]):
            return False, f"installed {ver} is not in the affected range (fixed)"
        return True, f"installed {ver} is affected (library range; not in feed)"
    return False, "no advisory for this component in the feed"


def build_policy(inventory, feed, site="", mode="log", log_path=None, max_log_bytes=5_000_000):
    rules, skipped = [], []
    for e in LIBRARY:
        ok, why = rule_status(e, inventory, feed)
        if not ok:
            skipped.append({"id": e["id"], "cve": e.get("cve"), "reason": why})
            continue
        rules.append({"id": e["id"], "cve": e.get("cve"), "component": _component_label(e["target"]),
                      "description": e["description"], "why": why, "mode": "log",
                      **({"method": e["method"]} if e.get("method") else {}),
                      **({"path": e["path"]} if e.get("path") else {}),
                      "all": e.get("all", [])})
    return {"version": POLICY_VERSION, "generator": f"phpwarden {__version__}",
            "created": int(time.time()), "site": site, "mode": "log" if mode != "enforce" else "enforce",
            "feed_version": getattr(feed, "feed_version", None),
            "log": {"path": log_path, "max_bytes": int(max_log_bytes)},
            "budget_ms": 5, "trust_proxy": False,
            "rules": rules, "skipped": skipped}


def _component_label(t):
    if t["type"] == "composer":
        return t["package"]
    if t["type"] in ("wp-plugin", "wp-theme"):
        return f"{t['type'][3:]} {t['slug']}"
    return {"wp-core": "WordPress core", "engine": "PHP engine", "generic": "any"}[t["type"]]


def inventory_for_path(path, php_version=None, php_sapi=None):
    """Inventory of a project or WordPress root on disk."""
    from phpwarden import wordpress as wp
    from phpwarden.deps import parse_composer_lock
    root = Path(path)
    inv = {"composer": {}, "wordpress": {}, "php": {"version": php_version, "sapi": php_sapi}}
    lock = root / "composer.lock"
    if lock.is_file():
        for name, ver in parse_composer_lock(str(lock)):
            inv["composer"][name] = ver
    comps = wp.inventory(str(root)) if (root / "wp-includes").is_dir() else []
    if comps:
        inv["wordpress"] = {"core": next((c.version for c in comps if c.kind == "core"), None),
                            "plugins": {c.slug: c.version for c in comps if c.kind == "plugin"},
                            "themes": {c.slug: c.version for c in comps if c.kind == "theme"}}
    return inv


def build_policy_for_path(path, feed, **kw):
    php = {k: kw.pop(k) for k in ("php_version", "php_sapi") if k in kw}
    return build_policy(inventory_for_path(path, **php), feed, site=str(path), **kw)


def promote(policy, stats, operator_ack=False, rule_ids=None, now=None, min_days=BURN_IN_DAYS):
    """Move rules from log to block after a clean burn-in. Returns (policy, report).

    A rule is promoted only when ALL hold: the operator acknowledged (explicit
    flag), the policy has been logging for at least `min_days`, and the rule is
    not flagged noisy in `stats` (from report.summarize: hits spread across many
    ordinary-looking paths). Never called automatically."""
    now = int(now or time.time())
    report = {"promoted": [], "refused": []}
    if not operator_ack:
        report["refused"] = [{"id": r["id"], "reason": "operator acknowledgement required"} for r in policy["rules"]]
        return policy, report
    age_days = (now - int(policy.get("created") or now)) / 86400
    noisy = set((stats or {}).get("noisy_rules", []))
    for r in policy["rules"]:
        if rule_ids and r["id"] not in rule_ids:
            continue
        if age_days < min_days:
            report["refused"].append({"id": r["id"], "reason": f"burn-in {age_days:.1f} of {min_days} days"})
        elif r["id"] in noisy:
            report["refused"].append({"id": r["id"], "reason": "noisy during burn-in; review its hits"})
        else:
            r["mode"] = "block"
            r["promoted_at"] = now
            report["promoted"].append(r["id"])
    if report["promoted"]:
        policy["mode"] = "enforce"
    return policy, report


def write_policy(policy, path):
    """Write policy JSON, plus a .php twin the agent can load from opcache."""
    p = Path(path)
    p.write_text(json.dumps(policy, indent=1))
    php = p.with_suffix(".php")
    php.write_text("<?php return json_decode(" + _php_str(json.dumps(policy)) + ", true);\n")
    return str(p), str(php)


def _php_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
