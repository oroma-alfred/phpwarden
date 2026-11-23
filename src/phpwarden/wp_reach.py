"""WordPress reachability: is the vulnerable code path in use on this site?

For each vulnerable plugin/theme finding we decide one of three labels:

  reachable             the vulnerable entry point is live on this site
  likely not reachable  we have positive evidence it is not in use (always with a reason)
  unknown               the default whenever we are not sure

Reachability never removes a finding. KEV findings stay first; inside each
exploitation tier, reachable findings sort before unknown, and unknown before
likely-not-reachable.

Signals come from a "site state" that either the CLI builds (files + an
optional database read through wp-config.php) or the WordPress plugin sends in
its opt-in `usage` field. Both feed the same evaluate() so they agree.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

REACHABLE = "reachable"
NOT_REACHABLE = "likely not reachable"
UNKNOWN = "unknown"
_ORDER = {REACHABLE: 0, UNKNOWN: 1, NOT_REACHABLE: 2}

# --------------------------------------------------------------------------
# Curated vector map. The feed does not carry the affected component, so for
# the most common and the KEV-listed plugin CVEs we record how the bug is
# reached. Vector kinds:
#   file       a PHP file inside the plugin is requested directly; WordPress
#              does not need to load the plugin, so "inactive" does not help
#   always     reached on every request once the plugin is active (init hooks,
#              cookies, global filters)
#   shortcode  only pages that embed one of `names` expose it
#   ajax       admin-ajax.php action(s) in `names` (nopriv = unauthenticated)
#   rest       REST namespace(s) in `names`
#   block      block name(s) in `names` embedded in content
#   option     an admin setting (`option`) must be enabled
# `files` (for file vectors) are paths relative to the plugin directory.
VECTORS: Dict[str, dict] = {
    "CVE-2020-25213": {"slug": "wp-file-manager", "kind": "file",
                       "files": ["lib/php/connector.minimal.php"],
                       "note": "elFinder connector file is requested directly"},
    "CVE-2024-28000": {"slug": "litespeed-cache", "kind": "always",
                       "note": "role-simulation cookie is checked on every request"},
    "CVE-2020-35489": {"slug": "contact-form-7", "kind": "shortcode",
                       "names": ["contact-form-7", "contact-form"],
                       "blocks": ["contact-form-7/contact-form-selector"],
                       "note": "only forms placed on a page accept uploads"},
    "CVE-2023-3460": {"slug": "ultimate-member", "kind": "shortcode",
                      "names": ["ultimatemember"],
                      "note": "needs a registration or profile form on a page"},
    "CVE-2024-27956": {"slug": "wp-automatic", "kind": "file",
                       "files": ["inc/csv.php"],
                       "note": "inc/csv.php is requested directly"},
    "CVE-2023-6553": {"slug": "backup-backup", "kind": "file",
                      "files": ["includes/backup-heart.php"],
                      "note": "backup-heart.php is requested directly"},
    "CVE-2024-25600": {"slug": "bricks", "type": "theme", "kind": "rest",
                       "names": ["bricks/v1"],
                       "note": "REST route bricks/v1/render_element"},
    "CVE-2023-28121": {"slug": "woocommerce-payments", "kind": "always",
                       "note": "spoofed request header is read on every request"},
}


@dataclass
class SiteState:
    """What we know about how the site uses its software. None = not known."""
    active_plugins: Optional[Set[str]] = None   # slugs; mu-plugins included
    mu_plugins: Set[str] = field(default_factory=set)
    active_themes: Optional[Set[str]] = None    # stylesheet + template
    shortcodes_used: Optional[Set[str]] = None  # names seen in published content
    blocks_used: Optional[Set[str]] = None      # e.g. "contact-form-7/contact-form-selector"
    rest_namespaces: Optional[Set[str]] = None
    ajax_actions: Optional[Set[str]] = None
    ajax_complete: bool = True                  # False: list may miss admin-only hooks
    options_on: Optional[Set[str]] = None
    source: str = "files"                       # files | database | plugin-report
    notes: List[str] = field(default_factory=list)


@dataclass
class Reach:
    status: str
    reasons: List[str]

    def to_dict(self) -> dict:
        return {"status": self.status, "reasons": self.reasons}


# --------------------------------------------------------------------------
# Evaluation

def _registered_in_code(comp_dir: Optional[Path], vec: dict) -> Optional[bool]:
    """Does the installed code register the vector's name? None = can't tell."""
    if comp_dir is None or not comp_dir.is_dir() or not vec.get("names"):
        return None
    kind = vec["kind"]
    pats = []
    for n in vec["names"]:
        q = re.escape(n)
        if kind == "shortcode":
            pats.append(rf"add_shortcode\s*\(\s*['\"]{q}['\"]")
        elif kind == "ajax":
            pats.append(rf"['\"]wp_ajax_(?:nopriv_)?{q}['\"]")
        elif kind == "rest":
            pats.append(rf"['\"]{q}['\"]")
    if not pats:
        return None
    rx = re.compile("|".join(pats))
    for php in _php_files(comp_dir):
        try:
            if rx.search(php.read_text(errors="replace")):
                return True
        except OSError:
            continue
    return False


def _php_files(d: Path, limit: int = 4000) -> Iterable[Path]:
    n = 0
    for p in d.rglob("*.php"):
        if "vendor" in p.parts or "node_modules" in p.parts:
            continue
        yield p
        n += 1
        if n >= limit:
            return


def evaluate(kind: str, slug: str, cve: str, state: SiteState,
             comp_dir: Optional[Path] = None) -> Reach:
    """Reachability of one finding. kind: core | plugin | theme."""
    if kind == "core":
        return Reach(UNKNOWN, ["WordPress core always runs; no reachability check"])
    vec = VECTORS.get(cve)
    if vec and vec["slug"] != slug.lower().replace("_", "-"):
        vec = None
    active = _is_active(kind, slug, state)

    if vec and vec["kind"] == "file":
        files = vec.get("files", [])
        if comp_dir is not None and files:
            present = [f for f in files if (comp_dir / f).is_file()]
            if present:
                return Reach(REACHABLE, [f"{vec['note']} ({present[0]} is on disk); "
                                         "this works even when the plugin is inactive"])
            return Reach(NOT_REACHABLE, [f"the vulnerable file {files[0]} is not on disk "
                                         "(removed or never shipped)"])
        return Reach(UNKNOWN, [f"{vec['note']}; works even when inactive, files not checked"])

    if active is False:
        what = "theme" if kind == "theme" else "plugin"
        return Reach(NOT_REACHABLE, [f"{what} is installed but not active{_SRC.get(state.source, "")}; "
                                     "WordPress does not load its code. Delete it to be sure: "
                                     "a PHP file that lacks a direct-access guard can still be requested"])
    if active is None:
        base = ["active state not known (no database access or plugin report)"]
        if vec:
            base.append(f"vector: {vec['note']}")
        return Reach(UNKNOWN, base)

    # active from here on
    if slug in state.mu_plugins:
        lead = "must-use plugin, always loaded"
    else:
        lead = f"{'theme' if kind == 'theme' else 'plugin'} is active"
    if not vec:
        return Reach(REACHABLE, [lead + "; no curated vector for this CVE, so any active "
                                 "plugin code is treated as reachable"])
    vk = vec["kind"]
    if vk == "always":
        return Reach(REACHABLE, [f"{lead}; {vec['note']}"])

    reg = _registered_in_code(comp_dir, vec)
    if vk == "shortcode":
        used = state.shortcodes_used
        blocks = state.blocks_used
        hit = sorted(set(vec["names"]) & used) if used is not None else []
        bhit = sorted(set(vec.get("blocks", [])) & blocks) if blocks is not None else []
        if hit or bhit:
            return Reach(REACHABLE, [f"{lead}; {'shortcode [' + hit[0] + ']' if hit else 'block ' + bhit[0]} "
                                     "is used in published content"])
        if reg is False:
            return Reach(UNKNOWN, [f"{lead}; the installed code does not register "
                                   f"[{vec['names'][0]}], so the curated vector may be out of date"])
        if used is not None and (blocks is not None or not vec.get("blocks")):
            return Reach(NOT_REACHABLE, [f"{lead}, but no published post or page uses "
                                         f"{', '.join('[' + n + ']' for n in vec['names'])}"
                                         f"{' or its block' if vec.get('blocks') else ''}; {vec['note']}. "
                                         "Theme templates and widgets calling do_shortcode() are checked "
                                         "only on the CLI"])
        return Reach(UNKNOWN, [f"{lead}; content was not checked for "
                               f"[{vec['names'][0]}] ({vec['note']})"])
    if vk in ("ajax", "rest"):
        have = state.ajax_actions if vk == "ajax" else state.rest_namespaces
        label = "AJAX action" if vk == "ajax" else "REST namespace"
        if have is not None:
            hit = sorted(set(vec["names"]) & have)
            if hit:
                return Reach(REACHABLE, [f"{lead}; {label} {hit[0]} is registered"])
            if vk == "ajax" and not state.ajax_complete:
                return Reach(UNKNOWN, [f"{lead}; {label} {vec['names'][0]} not seen in the report "
                                       "(plugins may register it only on admin requests)"])
            return Reach(NOT_REACHABLE, [f"{lead}, but {label} {vec['names'][0]} is not registered "
                                         f"on this site; {vec['note']}"])
        if reg:
            return Reach(REACHABLE, [f"{lead}; the code registers {label} {vec['names'][0]}"])
        if reg is False:
            return Reach(UNKNOWN, [f"{lead}; {label} {vec['names'][0]} not found in the code, "
                                   "the curated vector may be out of date"])
        return Reach(REACHABLE, [f"{lead}; {label} {vec['names'][0]} registers when active"])
    if vk == "block":
        if state.blocks_used is not None:
            hit = sorted(set(vec["names"]) & state.blocks_used)
            if hit:
                return Reach(REACHABLE, [f"{lead}; block {hit[0]} is used in published content"])
            return Reach(NOT_REACHABLE, [f"{lead}, but block {vec['names'][0]} is not used in "
                                         f"published content; {vec['note']}"])
        return Reach(UNKNOWN, [f"{lead}; block usage not checked"])
    if vk == "option":
        if state.options_on is not None:
            if vec["option"] in state.options_on:
                return Reach(REACHABLE, [f"{lead}; setting {vec['option']} is enabled"])
            return Reach(NOT_REACHABLE, [f"{lead}, but the vulnerable setting {vec['option']} "
                                         f"is off; {vec['note']}"])
        return Reach(UNKNOWN, [f"{lead}; setting {vec['option']} not checked"])
    return Reach(UNKNOWN, [lead])


_SRC = {"plugin-report": " (from the phpwarden plugin's report)",
        "database": " (from the site's database)"}


def _is_active(kind: str, slug: str, state: SiteState) -> Optional[bool]:
    s = slug.lower()
    if kind == "plugin":
        if s in state.mu_plugins:
            return True
        return None if state.active_plugins is None else s in state.active_plugins
    if kind == "theme":
        return None if state.active_themes is None else s in state.active_themes
    return None


_CODE = {REACHABLE: "wp-reachable", NOT_REACHABLE: "wp-unlikely"}


def encode(status: str, reasons) -> str:
    """Compact form for the dashboard's `reach` column: "wp-reachable|reason",
    "wp-unlikely|reason", or "" for unknown (no badge)."""
    code = _CODE.get(status)
    if not code:
        return ""
    reason = re.sub(r"[\s|]+", " ", "; ".join(reasons or [])).strip()[:300]
    return f"{code}|{reason}"


def encode_dict(d) -> str:
    """encode() from a CLI JSON `reachability` object (untrusted input)."""
    if not isinstance(d, dict):
        return ""
    r = d.get("reasons")
    return encode(str(d.get("status") or ""), [str(x) for x in r] if isinstance(r, list) else [])


def rank_key(known_exploited: bool, reach_status: str):
    """Prefix for the finding sort key: KEV tier first, then reachability."""
    return (0 if known_exploited else 1, _ORDER.get(reach_status, 1))


# --------------------------------------------------------------------------
# Site state from the WordPress plugin's report

def state_from_inventory(doc: dict) -> SiteState:
    """Build a SiteState from a /v1/inventory payload (plugin 1.3.0+)."""
    wp = doc.get("wordpress") if isinstance(doc.get("wordpress"), dict) else {}
    st = SiteState(source="plugin-report")
    plugins = [p for p in (wp.get("plugins") or []) if isinstance(p, dict)]
    themes = [t for t in (wp.get("themes") or []) if isinstance(t, dict)]
    if plugins and all("active" in p for p in plugins):
        st.active_plugins = {str(p.get("slug", "")).lower() for p in plugins if p.get("active")}
    if themes and all("active" in t for t in themes):
        st.active_themes = {str(t.get("slug", "")).lower() for t in themes if t.get("active")}
    usage = doc.get("usage") if isinstance(doc.get("usage"), dict) else None
    if usage:
        def names(key):
            v = usage.get(key)
            return {str(x)[:120] for x in v[:2000]} if isinstance(v, list) else None
        st.shortcodes_used = names("shortcodes_used")
        st.blocks_used = names("blocks_used")
        st.rest_namespaces = names("rest_namespaces")
        st.ajax_actions = names("ajax_actions")
        st.ajax_complete = False
    return st


# --------------------------------------------------------------------------
# Site state from files and (optionally) the database

_DEFINE_RE = re.compile(r"define\s*\(\s*['\"](DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['\"]\s*,\s*['\"]([^'\"]*)['\"]")
_PREFIX_RE = re.compile(r"\$table_prefix\s*=\s*['\"]([A-Za-z0-9_]+)['\"]")


def read_wp_config(wp_root: Path) -> Optional[dict]:
    for cand in (wp_root / "wp-config.php", wp_root.parent / "wp-config.php"):
        if cand.is_file():
            text = cand.read_text(errors="replace")
            cfg = {k: v for k, v in _DEFINE_RE.findall(text)}
            m = _PREFIX_RE.search(text)
            cfg["prefix"] = m.group(1) if m else "wp_"
            if "DB_NAME" in cfg:
                return cfg
    return None


class _Db:
    """Read-only queries through whatever MySQL client is installed."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.conn = None
        self.mode = None
        host = cfg.get("DB_HOST", "localhost")
        port = 3306
        sock = None
        if ":" in host:
            host, rest = host.split(":", 1)
            if rest.isdigit():
                port = int(rest)
            else:
                sock = rest
        self.host, self.port, self.sock = host or "localhost", port, sock
        try:
            import pymysql  # type: ignore
            kw = dict(user=cfg.get("DB_USER"), password=cfg.get("DB_PASSWORD"),
                      database=cfg["DB_NAME"], connect_timeout=5, charset="utf8mb4")
            kw.update({"unix_socket": sock} if sock else {"host": self.host, "port": port})
            self.conn = pymysql.connect(**kw)
            self.mode = "pymysql"
            return
        except Exception:  # noqa: BLE001
            pass
        if shutil.which("mysql"):
            self.mode = "cli"

    def query(self, sql: str) -> Optional[List[List[str]]]:
        if self.mode == "pymysql":
            try:
                with self.conn.cursor() as c:
                    c.execute(sql)
                    return [[("" if v is None else (v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)))
                             for v in row] for row in c.fetchall()]
            except Exception:  # noqa: BLE001
                return None
        if self.mode == "cli":
            args = ["mysql", "--batch", "--skip-column-names", "--raw", "-u", self.cfg.get("DB_USER", ""),
                    self.cfg["DB_NAME"], "-e", sql]
            args[1:1] = ["--socket", self.sock] if self.sock else ["-h", self.host, "-P", str(self.port)]
            env = {"MYSQL_PWD": self.cfg.get("DB_PASSWORD", ""), "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=30, env=env)
            except (OSError, subprocess.TimeoutExpired):
                return None
            if r.returncode != 0:
                return None
            return [line.split("\t") for line in r.stdout.splitlines()]
        return None


def _php_unserialize_strings(s: str) -> List[str]:
    """Plugin files from a serialized active_plugins array (strings only)."""
    return re.findall(r's:\d+:"([^"]*)"', s or "")


def _slug_of(file: str) -> str:
    return file.split("/", 1)[0] if "/" in file else re.sub(r"\.php$", "", file)


def state_from_site(wp_root, shortcode_names: Iterable[str] = (), block_names: Iterable[str] = (),
                    db: Optional[object] = None) -> SiteState:
    """Files always; database when wp-config.php works with an available client.

    Only names are read: whether a shortcode/block appears in published
    content is a yes/no per name, content itself is never stored or printed.
    """
    root = Path(wp_root)
    st = SiteState(source="files")
    mu = root / "wp-content" / "mu-plugins"
    if mu.is_dir():
        st.mu_plugins = {p.name.lower() if p.is_dir() else p.stem.lower()
                         for p in mu.iterdir() if p.is_dir() or p.suffix == ".php"}
    if db is None:
        cfg = read_wp_config(root)
        if not cfg:
            st.notes.append("no wp-config.php with DB settings: active state unknown")
            return st
        db = _Db(cfg)
        if not db.mode:
            st.notes.append("no MySQL client (pip install pymysql, or the mysql CLI): active state unknown")
            return st
        prefix = cfg["prefix"]
    else:
        prefix = getattr(db, "prefix", "wp_")
    if not re.fullmatch(r"[A-Za-z0-9_]+", prefix):
        return st
    rows = db.query(f"SELECT option_name, option_value FROM {prefix}options "
                    "WHERE option_name IN ('active_plugins','stylesheet','template')")
    if rows is None:
        st.notes.append("database not reachable with wp-config.php settings: active state unknown")
        return st
    st.source = "database"
    opts = {r[0]: (r[1] if len(r) > 1 else "") for r in rows}
    st.active_plugins = {_slug_of(f).lower() for f in _php_unserialize_strings(opts.get("active_plugins", ""))}
    st.active_plugins |= st.mu_plugins
    sw = db.query(f"SELECT meta_value FROM {prefix}sitemeta WHERE meta_key='active_sitewide_plugins'")
    if sw:
        for r in sw:
            st.active_plugins |= {_slug_of(f).lower() for f in _php_unserialize_strings(r[0])}
    st.active_themes = {v.lower() for v in (opts.get("stylesheet"), opts.get("template")) if v}

    def used(pattern_for, names):
        out = set()
        for n in names:
            if not re.fullmatch(r"[A-Za-z0-9_\-/]+", n):
                continue
            like = pattern_for(n).replace("_", r"\_")
            r = db.query(f"SELECT 1 FROM {prefix}posts WHERE post_status='publish' "
                         f"AND post_content LIKE '{like}' LIMIT 1")
            if r is None:
                return None
            w = db.query(f"SELECT 1 FROM {prefix}options WHERE option_name LIKE 'widget\\_%' "
                         f"AND option_value LIKE '{like}' LIMIT 1")
            if r or w:
                out.add(n)
        return out
    st.shortcodes_used = used(lambda n: f"%[{n}%", shortcode_names)
    st.blocks_used = used(lambda n: f"%<!-- wp:{n}%", block_names)
    if st.shortcodes_used is not None:
        st.shortcodes_used |= _shortcodes_in_theme(root, st.active_themes, shortcode_names)
    return st


def _shortcodes_in_theme(root: Path, themes: Set[str], names: Iterable[str]) -> Set[str]:
    """Shortcodes the active theme renders from templates via do_shortcode()."""
    names = [n for n in names if re.fullmatch(r"[A-Za-z0-9_\-]+", n)]
    if not names:
        return set()
    rx = re.compile(r"do_shortcode\s*\(\s*['\"]\[(" + "|".join(map(re.escape, names)) + r")\b")
    out = set()
    for t in themes:
        d = root / "wp-content" / "themes" / t
        if d.is_dir():
            for php in _php_files(d, 2000):
                try:
                    out |= set(rx.findall(php.read_text(errors="replace")))
                except OSError:
                    pass
    return out


def names_for(findings) -> (List[str], List[str]):
    """Shortcode and block names worth checking for these findings."""
    sc, bl = [], []
    for f in findings:
        v = VECTORS.get(f.advisory.cve)
        if v and v["kind"] == "shortcode":
            sc += v["names"]
            bl += v.get("blocks", [])
        elif v and v["kind"] == "block":
            bl += v["names"]
    return sorted(set(sc)), sorted(set(bl))


def apply(wp_root, findings, state: Optional[SiteState] = None):
    """Annotate WpFindings with .reach and re-sort. Returns (findings, state)."""
    root = Path(wp_root)
    if state is None:
        sc, bl = names_for(findings)
        state = state_from_site(root, sc, bl)
    for f in findings:
        c = f.component
        d = None
        if c.kind == "plugin":
            for base in ("plugins", "mu-plugins"):
                p = root / "wp-content" / base / c.slug
                if p.is_dir():
                    d = p
                    break
        elif c.kind == "theme":
            d = root / "wp-content" / "themes" / c.slug
        f.reach = evaluate(c.kind, c.slug, f.advisory.cve, state, d)
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: rank_key(f.advisory.known_exploited, f.reach.status) + (
        -(f.advisory.epss or 0), sev.get(f.advisory.severity, 9), -f.advisory.cvss))
    return findings, state


def load_inventory(path) -> SiteState:
    return state_from_inventory(json.loads(Path(path).read_text()))
