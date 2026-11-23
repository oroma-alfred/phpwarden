"""Minimal fix for Composer: the smallest version change that removes each
exploited finding in a composer.lock.

For every vulnerable package whose findings are exploited (CISA KEV) or likely
exploited (EPSS >= 0.5), the resolver picks the lowest version that is outside
the affected range of every targeted advisory, preferring the installed major
version. It then checks that version against:

  * the root composer.json constraint for the package (require / require-dev),
  * the "require" entries of every other package in the lockfile,
  * the "conflict" entries of every other package in the lockfile.

Candidates come from the advisories' fixed versions, which ship in the feed, so
the resolver works offline. Packagist metadata (the list of released versions)
is optional: when enabled it is fetched once per package and cached on disk,
and only then does the plan say the target is a real release.

The resolver never guesses. A fix that needs a major bump, a root constraint
change or that conflicts with another locked package is reported with the
reason, and only clean fixes get a `composer update` command.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from phpwarden import version as V
from phpwarden.deps import DepFinding, _satisfies_one, constraint_matches

LIKELY_EPSS = 0.5
PACKAGIST_URL = "https://repo.packagist.org/p2/{name}.json"
PACKAGIST_TTL = 24 * 3600

# status values, from best to worst
OK = "ok"                    # composer update within the current constraints
ROOT = "root-constraint"     # fix is in the same major, composer.json must widen
MAJOR = "major-bump"         # no fixed release in the installed major
CONFLICT = "conflict"        # another locked package forbids the fixed version
NOFIX = "no-fix"             # the advisory lists no fixed version


# --- composer constraint evaluation ----------------------------------------- #

def _bump(t, idx):
    t = list(t) + [0] * (idx + 1 - len(t))
    return tuple(t[:idx]) + (t[idx] + 1,)


def _expand_token(tok: str) -> Optional[List[str]]:
    """One composer constraint token as plain comparators ("^1.2" -> [">=1.2", "<2"]).
    None when the token cannot be evaluated (dev branches)."""
    tok = tok.strip()
    tok = re.sub(r"@(dev|alpha|beta|rc|RC|stable)$", "", tok)
    if not tok or tok in ("*", "x", "X"):
        return []
    if tok.startswith("dev-") or tok.endswith("-dev") and not re.match(r"[<>=^~]", tok):
        return None
    if tok[0] in "^~":
        base = tok[1:].lstrip("vV")
        t = V.parse_loose(re.sub(r"\.(\*|x|X)$", "", base))
        if t is None:
            return None
        nseg = len(base.split("."))
        if tok[0] == "^":
            idx = next((i for i, x in enumerate(t) if x != 0), len(t) - 1)
            if idx >= nseg:
                idx = nseg - 1
            upper = _bump(t, idx)
        else:  # tilde: last given segment may move, the one before is fixed
            upper = _bump(t, max(nseg - 2, 0))
        lo = ".".join(str(x) for x in t)
        hi = ".".join(str(x) for x in upper)
        return [f">={lo}", f"<{hi}"]
    if re.match(r"^[vV]?\d", tok) and not re.search(r"[*xX]$", tok):
        return ["=" + tok.lstrip("vV")]
    return [tok]


def composer_allows(ver: str, constraint: str) -> Optional[bool]:
    """Does version `ver` satisfy composer constraint `constraint`?

    Handles ^, ~, wildcards, hyphen ranges, comparators, "," / space (AND) and
    "|" / "||" (OR). Returns None when the constraint cannot be evaluated (a
    dev branch, say), so callers can say so instead of guessing."""
    vt = V.parse_loose(ver)
    if vt is None or constraint is None:
        return None
    constraint = re.sub(r"\s+as\s+\S+", "", constraint.strip())
    unknown = False
    for group in re.split(r"\s*\|\|?\s*", constraint):
        group = group.strip()
        if not group:
            continue
        hy = re.fullmatch(r"(\S+)\s+-\s+(\S+)", group)
        if hy:
            comps = [">=" + hy.group(1), "<=" + hy.group(2)]
        else:
            group = re.sub(r"(>=|<=|!=|==|>|<|=)\s+", r"\1", group)
            comps = []
            bad = False
            for tok in re.split(r"[,\s]+", group):
                if not tok:
                    continue
                e = _expand_token(tok)
                if e is None:
                    bad = True
                    break
                comps.extend(e)
            if bad:
                unknown = True
                continue
        if all(_satisfies_one(vt, c) for c in comps):
            return True
    return None if unknown else False


# --- Packagist metadata (optional, cached) ---------------------------------- #

def _cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "phpwarden" / "packagist"


class Packagist:
    """Released versions per package from Packagist's p2 metadata, cached on
    disk for 24 hours. `offline=True` reads only the cache."""

    def __init__(self, cache_dir=None, offline=False, ttl=PACKAGIST_TTL, timeout=10):
        self.cache_dir = Path(cache_dir) if cache_dir else _cache_dir()
        self.offline, self.ttl, self.timeout = offline, ttl, timeout
        self.errors: List[str] = []

    def _path(self, name):
        return self.cache_dir / (name.replace("/", "~") + ".json")

    def versions(self, name: str) -> Optional[List[str]]:
        p = self._path(name)
        doc = None
        if p.exists() and (self.offline or time.time() - p.stat().st_mtime < self.ttl):
            try:
                doc = json.loads(p.read_text())
            except ValueError:
                doc = None
        if doc is None and not self.offline:
            try:
                req = urllib.request.Request(PACKAGIST_URL.format(name=name),
                                             headers={"User-Agent": "phpwarden-fix"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read()
                doc = json.loads(raw)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(raw)
            except Exception as e:  # noqa: BLE001  (Packagist is optional)
                self.errors.append(f"{name}: {e}")
                if p.exists():
                    try:
                        doc = json.loads(p.read_text())
                    except ValueError:
                        doc = None
        if doc is None:
            return None
        return versions_from_p2(doc, name)


def versions_from_p2(doc: dict, name: str) -> List[str]:
    """Stable release versions from a Packagist p2 document (minified or not:
    every entry carries "version")."""
    out = []
    for e in (doc.get("packages") or {}).get(name, []) or []:
        v = str(e.get("version") or "").lstrip("vV")
        if not v or "dev" in v.lower() or re.search(r"(?i)(alpha|beta|rc)", v):
            continue
        if V.parse_loose(v) is not None:
            out.append(v)
    return out


# --- the resolver ------------------------------------------------------------ #

@dataclass
class Fix:
    package: str
    installed: str
    status: str
    target: Optional[str]
    cves: List[str]
    kev: List[str]
    epss: Optional[float]
    dev: bool = False
    reason: str = ""
    root_constraint: Optional[str] = None
    command: Optional[str] = None
    lowest_any_major: Optional[str] = None
    verified_release: Optional[bool] = None
    advisories: List[dict] = field(default_factory=list)

    def to_dict(self):
        return dict(self.__dict__)


def is_target(f: DepFinding, only: str = "likely") -> bool:
    a = f.advisory
    if only == "all":
        return True
    if a.known_exploited:
        return True
    return only == "likely" and (a.epss or 0) >= LIKELY_EPSS


def _major(t):
    return t[0] if t else 0


def _key(v):
    return V.parse_loose(v)


def _caret(v: str) -> str:
    t = _key(v)
    segs = [str(x) for x in t[:3]]
    while len(segs) < 2:
        segs.append("0")
    return "^" + ".".join(segs)


def _locked(lock_doc):
    out = {}
    for section in ("packages", "packages-dev"):
        for p in lock_doc.get(section, []) or []:
            if p.get("name"):
                out[p["name"]] = (p, section == "packages-dev")
    return out


def plan(findings: List[DepFinding], lock_doc: dict, composer_json: Optional[dict] = None,
         packagist: Optional[Packagist] = None, only: str = "likely") -> List[Fix]:
    """One Fix per vulnerable package that has a targeted finding, exploited first."""
    composer_json = composer_json or {}
    root_req = dict(composer_json.get("require-dev") or {})
    root_req.update(composer_json.get("require") or {})
    root_dev = set((composer_json.get("require-dev") or {})) - set(composer_json.get("require") or {})
    locked = _locked(lock_doc)

    by_pkg: Dict[str, List[DepFinding]] = {}
    for f in findings:
        if is_target(f, only):
            by_pkg.setdefault(f.package, []).append(f)

    fixes = []
    for name, fs in by_pkg.items():
        installed = fs[0].installed
        it = _key(installed)
        advs = [f.advisory for f in fs]
        kev = sorted({a.cve for a in advs if a.known_exploited and a.cve})
        cves = sorted({a.cve or a.title for a in advs})
        epss = max((a.epss or 0 for a in advs), default=0) or None
        dev = (locked.get(name, (None, False))[1]) or name in root_dev
        fx = Fix(name, installed, NOFIX, None, cves, kev, epss, dev=dev,
                 root_constraint=root_req.get(name),
                 advisories=[{"cve": a.cve, "known_exploited": a.known_exploited, "epss": a.epss,
                              "cvss": a.cvss, "affected": a.affected, "fixed": a.fixed} for a in advs])
        fixes.append(fx)

        nofix = [a.cve for a in advs if not a.fixed]
        if nofix:
            fx.reason = (f"{', '.join(nofix)} lists no fixed version; no upgrade is known to remove it. "
                         "Remove or replace the package, or use phpwarden shield as a virtual patch.")
            continue

        def clean(v):
            return all(not constraint_matches(v, a.affected) for a in advs)

        released = packagist.versions(name) if packagist else None
        pool = set()
        for a in advs:
            pool.update(x.lstrip("vV") for x in a.fixed)
        if released:
            pool.update(released)
        cands = sorted((v for v in pool if _key(v) and V.compare_loose(_key(v), it) > 0 and clean(v)),
                       key=_key)
        if released is not None:
            rel = set(released)
            cands = [v for v in cands if v in rel] or cands
        if not cands:
            fx.reason = ("no version above the installed one is outside every affected range "
                         "in the feed")
            continue
        same = [v for v in cands if _major(_key(v)) == _major(it)]
        fx.lowest_any_major = cands[0]
        if not same:
            fx.status, fx.target = MAJOR, cands[0]
            if released is not None:
                fx.verified_release = cands[0] in set(released)
            fx.reason = (f"no fixed release in {_major(it)}.x; the lowest fix is {cands[0]} "
                         f"(major {_major(_key(cands[0]))}). A major upgrade can break your code, "
                         "so phpwarden does not pick it for you.")
            continue
        target = same[0]
        fx.target = target
        if released is not None:
            fx.verified_release = target in set(released)

        blockers = []
        for other, (p, _d) in locked.items():
            if other == name:
                continue
            req = (p.get("require") or {}).get(name)
            if req and composer_allows(target, req) is False:
                blockers.append(f"{other} {p.get('version', '').lstrip('vV')} requires {name} {req}")
            con = (p.get("conflict") or {}).get(name)
            if con and composer_allows(target, con) is True:
                blockers.append(f"{other} {p.get('version', '').lstrip('vV')} conflicts with {name} {con}")
        if blockers:
            fx.status = CONFLICT
            fx.reason = (f"{target} would remove the finding, but " + "; ".join(blockers)
                         + ". Upgrade or replace that package first.")
            continue

        rc = fx.root_constraint
        allowed = composer_allows(target, rc) if rc else True
        flag = " --dev" if dev and rc else ""
        if rc and allowed is False:
            fx.status = ROOT
            fx.reason = (f"composer.json requires {name} {rc}, which excludes {target}; "
                         f"widen it to {_caret(target)}.")
            fx.command = f"composer require{flag} {name}:{_caret(target)} --with-dependencies"
        else:
            fx.status = OK
            if rc and allowed is None:
                fx.reason = f"could not evaluate the composer.json constraint {rc}; check it allows {target}."
            fx.command = f"composer update {name}:{_caret(target)} --with-dependencies"

    fixes.sort(key=lambda x: (0 if x.kev else 1, -(x.epss or 0), x.package))
    return fixes


def commands(fixes: List[Fix]) -> List[str]:
    """The commands to run, combining every plain update into one call."""
    ups = [f"{f.package}:{_caret(f.target)}" for f in fixes if f.status == OK]
    out = []
    if ups:
        out.append("composer update " + " ".join(ups) + " --with-dependencies")
    out += [f.command for f in fixes if f.status == ROOT and f.command]
    return out


def apply(fixes: List[Fix], cwd, composer=None) -> int:
    """Run the plan's commands with Composer. Returns Composer's exit code, or
    127 when Composer is not installed."""
    import shlex
    exe = composer or shutil.which("composer")
    if not exe:
        return 127
    for cmd in commands(fixes):
        argv = shlex.split(cmd)
        argv[0] = exe
        rc = subprocess.call(argv, cwd=str(cwd))
        if rc:
            return rc
    return 0


def _pct(e):
    return f"{e * 100:.0f}%" if e is not None else "n/a"


def pr_body(fixes: List[Fix], lockfile="composer.lock") -> str:
    """Markdown pull request body for the clean fixes in `fixes`."""
    done = [f for f in fixes if f.status in (OK, ROOT)]
    skipped = [f for f in fixes if f.status not in (OK, ROOT)]
    lines = ["## phpwarden minimal fix", "",
             f"The smallest version changes in `{lockfile}` that remove exploited vulnerabilities. "
             "Each package moves to the lowest fixed release in its current major version.", "",
             "| Package | From | To | CVE | KEV | EPSS |", "|---|---|---|---|---|---|"]
    for f in done:
        for a in f.advisories:
            lines.append(f"| `{f.package}` | {f.installed} | {f.target} | {a['cve']} | "
                         f"{'yes' if a['known_exploited'] else 'no'} | {_pct(a['epss'])} |")
    if skipped:
        lines += ["", "### Not changed in this PR", ""]
        for f in skipped:
            lines.append(f"- `{f.package}` {f.installed} ({', '.join(f.cves)}): {f.status}. {f.reason}")
    lines += ["", "Commands:", "", "```"] + commands(fixes) + ["```", "",
              "Generated by `phpwarden fix`. KEV is the CISA Known Exploited Vulnerabilities "
              "catalog; EPSS is the probability of exploitation in the next 30 days."]
    return "\n".join(lines) + "\n"
