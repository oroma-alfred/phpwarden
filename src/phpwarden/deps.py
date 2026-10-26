"""Composer dependency scanning — the Snyk-gap closer for PHP shops.

Reads a composer.lock (exact pinned versions) and matches every package against
the feed's Composer advisories, using composer-style version constraints
(comma = AND, pipe = OR, operators >= > <= < =).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from phpwarden import version as V
from phpwarden.vulndb import ComposerAdvisory, Feed

# One comparator: optional operator, then a version or a wildcard (11.0.*, 1.x, *).
_TOKEN = re.compile(r"(>=|<=|==|!=|=|>|<)?\s*([0-9][0-9A-Za-z.\-+_*]*|\*)")
_WILD = re.compile(r"^(\d+(?:\.\d+)*)\.(?:\*|x|X)$")


def _satisfies_one(ver_tuple, comparator: str) -> bool:
    comparator = comparator.strip()
    if comparator in ("*", "x", "X"):
        return True
    m = _TOKEN.fullmatch(comparator)
    if not m:
        return False
    op, rhs_s = (m.group(1) or "="), m.group(2)
    w = _WILD.match(rhs_s)
    if w:
        # "11.0.*" means >=11.0,<11.1 regardless of any operator in front of it
        lower = V.parse_loose(w.group(1))
        upper = lower[:-1] + (lower[-1] + 1,)
        return V.compare_loose(ver_tuple, lower) >= 0 and V.compare_loose(ver_tuple, upper) < 0
    rhs = V.parse_loose(rhs_s)
    if rhs is None:
        return False
    c = V.compare_loose(ver_tuple, rhs)
    return {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0,
            "=": c == 0, "==": c == 0, "!=": c != 0}[op]


def _comparators(group: str):
    """Comparators of one AND-group. Composer joins them with ',' OR whitespace
    (">=6.3.0 <6.3.1" is common in advisories), and allows ">= 1.0" with a space,
    so tokenise instead of splitting on a single separator."""
    return [m.group(0).strip() for m in _TOKEN.finditer(group) if m.group(0).strip()]


def constraint_matches(ver_str: str, affected: str) -> bool:
    """True if version string `ver_str` satisfies any OR-group of `affected`.

    Uses loose dotted-version comparison so 2-, 3- and 4-segment ecosystem
    versions (Composer, WordPress) all work; "|" or "||" separates OR-groups.
    """
    vt = V.parse_loose(ver_str)
    if vt is None:
        return False
    for group in re.split(r"\|\|?", affected):
        comps = _comparators(group)
        if comps and all(_satisfies_one(vt, c) for c in comps):
            return True
    return False


@dataclass
class DepFinding:
    package: str
    installed: str
    advisory: ComposerAdvisory
    fixed: List[str]


def parse_composer_lock(path) -> List[tuple]:
    """Return [(package, version), ...] from a composer.lock."""
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return []
    out = []
    for section in ("packages", "packages-dev"):
        for pkg in doc.get(section, []) or []:
            name = pkg.get("name")
            ver = (pkg.get("version") or "").lstrip("v")
            if name and ver:
                out.append((name, ver))
    return out


# --- reachability: is a vulnerable package actually used in your code? ------- #
# Dependency scanners flag every CVE in the lockfile — most of the noise is in
# transitive or dev-only packages you never call. We read each package's declared
# PSR-4/PSR-0 namespaces from the lock and check whether the project's own source
# (comments stripped) references them. The result feeds the ranking that
# `rank_findings` applies and that the CLI / dashboard order follows:
#
#   1. known_exploited (KEV) first
#   2. reach: used > unknown > unreferenced > dev-only
#   3. EPSS descending
#   4. CVSS descending
#
# "unknown" ranks ABOVE "unreferenced" on purpose: a package we could not check
# (no autoload namespace, or no project source to scan) must not be demoted as
# if we had proven it unused. When the project directory does not exist or has
# no PHP sources, every package is "unknown".

REACH_ORDER = {"used": 0, "unknown": 1, "unreferenced": 2, "dev-only": 3}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def strip_php_comments(src: str) -> str:
    """Remove //, # and /* */ comments (docblocks included) from PHP source,
    leaving string literal contents untouched so `'// not a comment'` survives.
    Comment bodies are replaced by a single space so tokens never fuse."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"":                       # string literal: copy verbatim
            quote = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == quote:
                    break
                j += 1
            out.append(src[i:j + 1])
            i = j + 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif (c == "#" and not (i + 1 < n and src[i + 1] == "[")) or \
                (c == "/" and i + 1 < n and src[i + 1] == "/"):
            # `#[Attr]` is a PHP 8 attribute, not a comment — keep it
            j = src.find("\n", i)
            i = n if j < 0 else j         # keep the newline itself
            out.append(" ")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _package_meta(lock_doc: dict) -> dict:
    """{package: {"ns": [namespace prefixes], "dev": bool}} from a composer.lock."""
    meta = {}
    for section in ("packages", "packages-dev"):
        for pkg in lock_doc.get(section, []) or []:
            name = pkg.get("name")
            if not name:
                continue
            ns = set()
            au = pkg.get("autoload", {}) or {}
            for key in ("psr-4", "psr-0"):
                for prefix in (au.get(key, {}) or {}).keys():
                    p = prefix.rstrip("\\")
                    if p:
                        ns.add(p)
            meta[name] = {"ns": sorted(ns), "dev": section == "packages-dev"}
    return meta


def _project_source(project_dir, max_files=4000, max_bytes=24_000_000):
    """(concatenated comment-stripped PHP source, file count) for the project's
    own code, excluding vendor/ and caches. A missing directory yields ("", 0)."""
    import os
    skip = {"vendor", "node_modules", ".git", "var", "cache", "storage", "tests", "test"}
    buf, nbytes, nfiles = [], 0, 0
    if not Path(project_dir).is_dir():
        return "", 0
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d.lower() not in skip and not d.startswith(".")]
        for fn in files:
            if not fn.endswith((".php", ".inc", ".phtml")):
                continue
            try:
                data = Path(root, fn).read_text(errors="ignore")
            except OSError:
                continue
            buf.append(strip_php_comments(data))
            buf.append("\n")
            nbytes += len(data)
            nfiles += 1
            if nfiles >= max_files or nbytes >= max_bytes:
                return "".join(buf), nfiles
    return "".join(buf), nfiles


def analyze_reachability(lock_path, project_dir) -> dict:
    """{package: reach} with reach in used | dev-only | unreferenced | unknown.

    Every package is "unknown" when there is nothing to scan (the project dir is
    missing or has no PHP sources): absence of evidence is not "unreferenced".
    Namespaces that appear only inside comments do not count as used."""
    try:
        doc = json.loads(Path(lock_path).read_text())
    except (OSError, ValueError):
        return {}
    meta = _package_meta(doc)
    src, nfiles = _project_source(project_dir)
    if nfiles == 0:
        return {name: "unknown" for name in meta}
    out = {}
    for name, m in meta.items():
        if not m["ns"]:
            out[name] = "unknown"          # no autoload namespace to look for
            continue
        used = any((ns + "\\") in src for ns in m["ns"])
        out[name] = "used" if used else ("dev-only" if m["dev"] else "unreferenced")
    return out


def rank_findings(findings: List[DepFinding], reach: dict = None) -> List[DepFinding]:
    """Sort findings by the documented order: KEV first, then reach
    (used > unknown > unreferenced > dev-only), then EPSS desc, then CVSS desc.
    Packages absent from `reach` count as "unknown"."""
    reach = reach or {}
    return sorted(findings, key=lambda f: (
        0 if f.advisory.known_exploited else 1,
        REACH_ORDER.get(reach.get(f.package, "unknown"), REACH_ORDER["unknown"]),
        -(f.advisory.epss or 0),
        -(f.advisory.cvss or 0),
        _SEV_ORDER.get(f.advisory.severity, 9)))


def _installed_from_doc(doc: dict) -> List[tuple]:
    out = []
    for section in ("packages", "packages-dev"):
        for pkg in doc.get(section, []) or []:
            name = pkg.get("name")
            ver = (pkg.get("version") or "").lstrip("v")
            if name and ver:
                out.append((name, ver))
    return out


def _scan_installed(installed, feed: Feed) -> List[DepFinding]:
    by_pkg = {}
    for adv in feed.composer:
        by_pkg.setdefault(adv.package, []).append(adv)
    findings = []
    for name, ver_str in installed:
        if V.parse_loose(ver_str) is None:
            continue
        for adv in by_pkg.get(name, []):
            if constraint_matches(ver_str, adv.affected):
                findings.append(DepFinding(name, ver_str, adv, adv.fixed))
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (
        0 if f.advisory.known_exploited else 1,
        -(f.advisory.epss or 0),
        sev.get(f.advisory.severity, 9), -f.advisory.cvss))
    return findings


def scan_lock_doc(doc: dict, feed: Feed) -> List[DepFinding]:
    """Scan an already-parsed composer.lock dict (e.g. pasted into the web UI)."""
    return _scan_installed(_installed_from_doc(doc), feed)


def scan_lock(path, feed: Feed) -> List[DepFinding]:
    installed = parse_composer_lock(path)
    by_pkg = {}
    for adv in feed.composer:
        by_pkg.setdefault(adv.package, []).append(adv)
    findings = []
    for name, ver_str in installed:
        if V.parse_loose(ver_str) is None:
            continue
        for adv in by_pkg.get(name, []):
            if constraint_matches(ver_str, adv.affected):
                findings.append(DepFinding(name, ver_str, adv, adv.fixed))
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (
        0 if f.advisory.known_exploited else 1,          # actively exploited first
        -(f.advisory.epss or 0),                          # then by exploitation probability
        sev.get(f.advisory.severity, 9), -f.advisory.cvss))
    return findings
