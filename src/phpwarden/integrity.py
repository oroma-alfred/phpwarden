"""File integrity check for a WordPress install.

Answers "has this site's code been tampered with?" without malware signatures:

  * WordPress core files are compared with the official checksums from
    api.wordpress.org for the installed version;
  * every wordpress.org plugin is compared with the plugin-checksums service;
  * files that do not belong (extra PHP in wp-admin / wp-includes / a plugin, any
    PHP under wp-content/uploads) are listed;
  * modified and unexpected PHP files are checked for a small set of well-known
    backdoor idioms (eval of decoded data, request input passed to a code or
    command function, and so on).

This is not a signature-based malware scanner. A changed core file or a PHP file
in uploads is how most compromised sites show up; novel malware hidden in a
premium plugin or a theme (which have no public checksums) is not covered, and
the report says which components could not be verified.

Needs network access to wordpress.org. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from phpwarden import wordpress as wp

CORE_URL = "https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}"
PLUGIN_URL = "https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json"
_UA = "phpwarden-integrity"
_PHP_EXT = (".php", ".phtml", ".php5", ".php7", ".phar", ".pht")
_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_SCAN_BYTES = 2_000_000

# (id, description, pattern). Deliberately few and specific: each one is rare in
# legitimate code and common in real backdoors.
_INPUT = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"
_DECODE = r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|strrev|convert_uudecode)"
PATTERNS = [
    ("eval-decoded", "eval() of decoded or decompressed data",
     re.compile(r"\beval\s*\(\s*(?:@\s*)?" + _DECODE + r"\s*\(", re.I)),
    ("eval-input", "eval()/assert() of request input",
     re.compile(r"\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*)?" + _INPUT, re.I)),
    ("exec-input", "request input passed to a command function",
     re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*(?:@\s*)?" + _INPUT, re.I)),
    ("decode-input-exec", "decoded request input executed",
     re.compile(r"\b(?:eval|assert|system|exec|shell_exec|passthru)\s*\(\s*" + _DECODE + r"\s*\(\s*" + _INPUT, re.I)),
    ("preg-e", "preg_replace() with the /e (execute) modifier",
     re.compile(r"preg_replace\s*\(\s*(['\"])(.)(?:(?!\1).)*\2[a-zA-Z]*e[a-zA-Z]*\1", re.I | re.S)),
    ("create-function-input", "create_function() built from request input",
     re.compile(r"\bcreate_function\s*\([^)]*" + _INPUT, re.I)),
    ("variable-function-input", "request input called as a function",
     re.compile(_INPUT + r"\s*\[[^\]]+\]\s*\(", re.I)),
    ("upload-write", "uploaded file moved using a name taken from the request",
     re.compile(r"move_uploaded_file\s*\([^,]+,\s*[^)]*" + _INPUT, re.I)),
    ("long-encoded-blob", "very long encoded string passed to a decoder",
     re.compile(_DECODE + r"\s*\(\s*['\"][A-Za-z0-9+/=\\x]{1500,}['\"]", re.I)),
]


@dataclass
class Issue:
    kind: str          # modified | unexpected | missing | php-in-uploads
    component: str     # core | plugin:<slug> | uploads
    path: str          # relative to the WordPress root
    suspicious: List[str] = field(default_factory=list)   # pattern ids that matched


@dataclass
class Result:
    root: str
    core_version: Optional[str]
    issues: List[Issue] = field(default_factory=list)
    verified: List[str] = field(default_factory=list)      # components checked against checksums
    unverified: List[dict] = field(default_factory=list)   # {"component", "reason"}
    files_checked: int = 0

    @property
    def tampered(self) -> bool:
        return any(i.kind in ("modified", "unexpected", "php-in-uploads") for i in self.issues)


def _fetch_json(url: str, timeout: float = 20.0):
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 — fixed https hosts
        return json.loads(r.read().decode("utf-8", "replace"))


def _md5(path: Path) -> str:
    h = hashlib.md5()                                            # noqa: S324 — wordpress.org publishes md5
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def suspicious_patterns(path: Path) -> List[str]:
    """Ids of the backdoor idioms found in a file (empty for non-PHP or huge files)."""
    if path.suffix.lower() not in _PHP_EXT:
        return []
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return []
        text = path.read_text(errors="replace")
    except OSError:
        return []
    return [pid for pid, _, rx in PATTERNS if rx.search(text)]


def _walk(base: Path):
    """Regular files under base (no symlink following), as (relative posix path, Path)."""
    if not base.is_dir():
        return
    stack = [base]
    while stack:
        d = stack.pop()
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_symlink():
                continue
            if e.is_dir():
                stack.append(e)
            elif e.is_file():
                yield e.relative_to(base).as_posix(), e


def _is_php(rel: str) -> bool:
    return rel.lower().endswith(_PHP_EXT)


def _compare(result: Result, component: str, base: Path, root: Path, sums: Dict[str, List[str]],
             unexpected_php_only: bool, skip: Callable[[str], bool] = lambda rel: False):
    """Compare files under `base` with `sums` ({relative path: [accepted md5...]})."""
    seen = set()
    for rel, path in _walk(base):
        if skip(rel):
            continue
        result.files_checked += 1
        relroot = path.relative_to(root).as_posix()
        want = sums.get(rel)
        if want is None:
            if unexpected_php_only and not _is_php(rel):
                continue
            result.issues.append(Issue("unexpected", component, relroot, suspicious_patterns(path)))
            continue
        seen.add(rel)
        try:
            got = _md5(path)
        except OSError:
            continue
        if got not in want:
            result.issues.append(Issue("modified", component, relroot, suspicious_patterns(path)))
    for rel in sums:
        if rel not in seen and not skip(rel) and _is_php(rel) and not (base / rel).exists():
            result.issues.append(Issue("missing", component, (base / rel).relative_to(root).as_posix()))


def check(wp_root, locale: str = "en_US", plugins: bool = True,
          fetch: Callable[[str], dict] = _fetch_json) -> Result:
    root = Path(wp_root)
    core = wp.detect_core(root)
    res = Result(str(root), core)
    if not core:
        res.unverified.append({"component": "core", "reason": "no WordPress install found at that path"})
        return res

    # ---- core
    try:
        doc = fetch(CORE_URL.format(version=core, locale=locale))
        raw = doc.get("checksums") if isinstance(doc, dict) else None
        if isinstance(raw, dict) and locale in raw and isinstance(raw[locale], dict):
            raw = raw[locale]
        if not isinstance(raw, dict) or not raw:
            raise ValueError("no checksums for this version/locale")
        sums = {k: [v] for k, v in raw.items() if isinstance(v, str)}
        # wp-content is user territory (bundled themes/plugins get updated on their own)
        _compare(res, "core", root, root, sums, unexpected_php_only=True,
                 skip=lambda rel: rel.startswith("wp-content/") or rel in ("wp-config.php", ".htaccess")
                 or not (rel.startswith("wp-admin/") or rel.startswith("wp-includes/") or "/" not in rel))
        res.verified.append(f"core {core}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        res.unverified.append({"component": f"core {core}", "reason": f"checksums unavailable: {_why(e)}"})

    # ---- plugins
    pdir = root / "wp-content" / "plugins"
    if plugins and pdir.is_dir():
        for slug, version in sorted(wp.detect_plugins(root).items()):
            base = pdir / slug
            if not base.is_dir():        # single-file plugin: nothing published to compare against
                res.unverified.append({"component": f"plugin {slug}", "reason": "single-file plugin"})
                continue
            if not version or not _SAFE.match(slug) or not _SAFE.match(version):
                res.unverified.append({"component": f"plugin {slug}", "reason": "version not detected"})
                continue
            try:
                doc = fetch(PLUGIN_URL.format(slug=slug, version=version))
                files = doc.get("files") if isinstance(doc, dict) else None
                if not isinstance(files, dict) or not files:
                    raise ValueError("empty checksum list")
                sums = {}
                for rel, meta in files.items():
                    md5 = meta.get("md5") if isinstance(meta, dict) else None
                    sums[rel] = [md5] if isinstance(md5, str) else [m for m in (md5 or []) if isinstance(m, str)]
                _compare(res, f"plugin:{slug}", base, root, sums, unexpected_php_only=True)
                res.verified.append(f"plugin {slug} {version}")
            except urllib.error.HTTPError as e:
                reason = ("not on wordpress.org (premium or custom), cannot be verified" if e.code == 404
                          else f"checksums unavailable: HTTP {e.code}")
                res.unverified.append({"component": f"plugin {slug} {version}", "reason": reason})
            except (urllib.error.URLError, OSError, ValueError) as e:
                res.unverified.append({"component": f"plugin {slug} {version}",
                                       "reason": f"checksums unavailable: {_why(e)}"})

    # ---- themes have no public checksums: say so rather than imply they were checked
    for slug in sorted(wp.detect_themes(root)):
        res.unverified.append({"component": f"theme {slug}", "reason": "no public checksums for themes"})

    # ---- PHP where it should never be
    up = root / "wp-content" / "uploads"
    for rel, path in _walk(up):
        if _is_php(rel):
            res.issues.append(Issue("php-in-uploads", "uploads", path.relative_to(root).as_posix(),
                                    suspicious_patterns(path)))
    order = {"php-in-uploads": 0, "unexpected": 1, "modified": 2, "missing": 3}
    res.issues.sort(key=lambda i: (0 if i.suspicious else 1, order.get(i.kind, 9), i.path))
    return res


def _why(e: Exception) -> str:
    return str(getattr(e, "reason", "") or e)[:120] or e.__class__.__name__


def describe(pattern_id: str) -> str:
    for pid, text, _ in PATTERNS:
        if pid == pattern_id:
            return text
    return pattern_id


def to_doc(res: Result) -> dict:
    return {"integrity": res.root, "core_version": res.core_version, "tampered": res.tampered,
            "files_checked": res.files_checked,
            "issues": [{"kind": i.kind, "component": i.component, "path": i.path, "suspicious": i.suspicious}
                       for i in res.issues],
            "verified": res.verified, "unverified": res.unverified}
