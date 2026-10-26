"""WordPress exposure scanning — the Patchstack-gap closer.

Walks a WordPress install, reads the core version and every plugin/theme
version, and matches them against the feed's WordPress advisories using the same
loose constraint matching as the dependency scanner.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from phpwarden.deps import constraint_matches
from phpwarden.vulndb import Feed, WpAdvisory

_CORE_RE = re.compile(r"\$wp_version\s*=\s*'([^']+)'")
_STABLE_TAG_RE = re.compile(r"(?im)^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)")
_HEADER_VER_RE = re.compile(r"(?im)^\s*(?:\*\s*)?Version:\s*([0-9][0-9A-Za-z.\-]*)")
_PLUGIN_NAME_RE = re.compile(r"(?im)^\s*(?:\*\s*)?Plugin Name:\s*\S")


@dataclass
class WpComponent:
    kind: str        # core | plugin | theme
    slug: str
    version: str


@dataclass
class WpFinding:
    component: WpComponent
    advisory: WpAdvisory
    fixed: List[str]


def detect_core(wp_root: Path) -> Optional[str]:
    vf = wp_root / "wp-includes" / "version.php"
    if vf.exists():
        m = _CORE_RE.search(vf.read_text(errors="replace"))
        if m:
            return m.group(1)
    return None


def _plugin_version(plugin_dir: Path) -> Optional[str]:
    # The plugin header "Version:" is what WordPress itself runs and reports;
    # readme.txt "Stable tag" is the wp.org catalogue's idea of the latest
    # release and can be NEWER than what is installed (a readme updated without
    # the code) — preferring it hid a known-exploited wp-file-manager 6.8.
    for php in sorted(plugin_dir.glob("*.php")):
        m = _HEADER_VER_RE.search(php.read_text(errors="replace")[:4000])
        if m:
            return m.group(1)
    readme = plugin_dir / "readme.txt"
    if readme.exists():
        m = _STABLE_TAG_RE.search(readme.read_text(errors="replace"))
        if m and m.group(1).lower() != "trunk":
            return m.group(1)
    return None


def _single_file_plugin_version(php: Path) -> Optional[str]:
    """Version of a single-file plugin (wp-content/plugins/hello.php style):
    only a file carrying a "Plugin Name:" header counts, so stray helper .php
    files are not inventoried as plugins."""
    try:
        head = php.read_text(errors="replace")[:4000]
    except OSError:
        return None
    if not _PLUGIN_NAME_RE.search(head):
        return None
    m = _HEADER_VER_RE.search(head)
    return m.group(1) if m else None


def _plugins_in(pdir: Path) -> Dict[str, str]:
    """{slug: version} for every plugin directory and single-file plugin in
    one plugins folder. Slug = directory name, or the file stem for a
    single-file plugin (which is also how WordPress names it)."""
    out: Dict[str, str] = {}
    if not pdir.is_dir():
        return out
    for entry in sorted(pdir.iterdir()):
        if entry.is_dir():
            v = _plugin_version(entry)
            if v:
                out[entry.name] = v
        elif entry.is_file() and entry.suffix == ".php":
            v = _single_file_plugin_version(entry)
            if v:
                out.setdefault(entry.stem, v)
    return out


def detect_plugins(wp_root: Path) -> Dict[str, str]:
    """Inventory wp-content/plugins (directories AND single-file plugins) plus
    wp-content/mu-plugins — must-use plugins load unconditionally and cannot be
    deactivated, so a vulnerable one is always live. Both use the same
    "plugin" kind so they match the feed's plugin advisories."""
    out = _plugins_in(wp_root / "wp-content" / "plugins")
    for slug, ver in _plugins_in(wp_root / "wp-content" / "mu-plugins").items():
        out.setdefault(slug, ver)
    return out


def detect_themes(wp_root: Path) -> Dict[str, str]:
    out = {}
    tdir = wp_root / "wp-content" / "themes"
    if not tdir.is_dir():
        return out
    for d in sorted(tdir.iterdir()):
        style = d / "style.css"
        if d.is_dir() and style.exists():
            m = _HEADER_VER_RE.search(style.read_text(errors="replace")[:4000])
            if m:
                out[d.name] = m.group(1)
    return out


def inventory(wp_root) -> List[WpComponent]:
    root = Path(wp_root)
    comps = []
    core = detect_core(root)
    if core:
        comps.append(WpComponent("core", "wordpress", core))
    for slug, ver in detect_plugins(root).items():
        comps.append(WpComponent("plugin", slug, ver))
    for slug, ver in detect_themes(root).items():
        comps.append(WpComponent("theme", slug, ver))
    return comps


def _norm_slug(slug: str) -> str:
    """Normalise slug for matching: NVD CPE products use underscores, while
    WordPress.org (and real install directories) use dashes."""
    return slug.strip().lower().replace("_", "-")


def scan(wp_root, feed: Feed) -> List[WpFinding]:
    comps = inventory(wp_root)
    by_key = {}
    for adv in feed.wp:
        by_key.setdefault((adv.type, _norm_slug(adv.slug)), []).append(adv)
    findings = []
    for c in comps:
        for adv in by_key.get((c.kind, _norm_slug(c.slug)), []):
            if constraint_matches(c.version, adv.affected):
                findings.append(WpFinding(c, adv, adv.fixed))
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (
        0 if f.advisory.known_exploited else 1,
        -(f.advisory.epss or 0),
        sev.get(f.advisory.severity, 9), -f.advisory.cvss))
    return findings
