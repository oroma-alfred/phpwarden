#!/usr/bin/env python3
"""Build engine CVE entries from php-src NEWS files (per-branch ground truth).

php-src keeps one NEWS file per release branch (PHP-7.1 ... PHP-8.5). Each
release section lists the bugs it fixed, with "(CVE-YYYY-NNNN)" markers. The
first release on a branch that mentions a CVE is that branch's fixed version —
exactly the per-branch data the engine needs. CVSS, severity, publication date
and description are taken from the NVD JSON mirror (fkie-cad/nvd-json-data-feeds)
when reachable; otherwise entries carry what NEWS alone supports.

Usage:
  import_php_news.py --out engine-cves.json [--branches 7.1 ... 8.5]
                     [--news-dir DIR] [--nvd-dir DIR] [--min-year 2016] [--offline]

Only hosts under github.com / raw.githubusercontent.com are contacted.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import sys
import urllib.request
from pathlib import Path

RAW = "https://raw.githubusercontent.com"
DEFAULT_BRANCHES = ["5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"]
# End of security support per branch (php.net/supported-versions). A branch that
# was still supported when a CVE was fixed elsewhere but got no fix of its own is
# not affected (the bug does not exist there); a branch already past this date
# may be affected with no fix coming.
EOL = {
    "5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30",
    "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31",
    "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31", "8.5": "2029-12-31",
}
ALL_BRANCHES = sorted(EOL, key=lambda b: tuple(int(x) for x in b.split(".")))


def eol_affected_for(branches: dict, dates: dict) -> bool:
    """True when the branch just below the oldest fixed one was already EOL at fix time."""
    oldest = min(branches, key=lambda b: tuple(int(x) for x in b.split(".")))
    i = ALL_BRANCHES.index(oldest) if oldest in ALL_BRANCHES else -1
    if i <= 0:
        return True                      # nothing older we know about: stay conservative
    older = ALL_BRANCHES[i - 1]
    fix_date = min((d for d in dates.values() if d), default=None)
    if fix_date is None:
        return True
    return fix_date > EOL[older]

_VER_HDR = re.compile(r"^(\d{1,2} \w{3} \d{4}|\?\? \?\?\? \?\?\?\?),? PHP (\d+\.\d+\.\d+)\s*$")
_SECTION = re.compile(r"^- ([A-Za-z0-9_ /+-]+):\s*$")
_BULLET = re.compile(r"^  \. (.*)$")
_CONT = re.compile(r"^    (\S.*)$")
_CVE_PARENS = re.compile(r"\(((?:CVE-\d{4}-\d{4,7})(?:\s*,\s*CVE-\d{4}-\d{4,7})*)\)")
_GHSA = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "phpwarden-feedbuilder"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _vt(v: str):
    return tuple(int(x) for x in v.split("."))


def _date(hdr: str):
    m = re.match(r"(\d{1,2}) (\w{3}) (\d{4})", hdr)
    if not m:
        return None
    return f"{m.group(3)}-{_MONTHS[m.group(2)]:02d}-{int(m.group(1)):02d}"


def parse_news(text: str):
    """Yield (version, date, section, bullet_text) for every bullet."""
    version = date = section = None
    bullet = []

    def flush():
        if bullet and version:
            yield (version, date, section, " ".join(bullet))

    for line in text.splitlines():
        m = _VER_HDR.match(line)
        if m:
            yield from flush(); bullet = []
            date, version, section = _date(m.group(1)), m.group(2), None
            continue
        m = _SECTION.match(line)
        if m:
            yield from flush(); bullet = []
            section = m.group(1).strip()
            continue
        m = _BULLET.match(line)
        if m:
            yield from flush()
            bullet = [m.group(1).strip()]
            continue
        m = _CONT.match(line)
        if m and bullet:
            bullet.append(m.group(1).strip())
            continue
        if not line.strip():
            yield from flush(); bullet = []
    yield from flush()


def collect(branches, news_dir: Path | None, offline: bool):
    """Return {cve: {"branches": {b: fixed}, "dates": {...}, "sections": set, "texts": [...]}}"""
    out: dict = {}
    for b in branches:
        # NEWS changes with every release: always refetch, fall back to the
        # cached copy only when GitHub is unreachable (or --offline).
        local = (news_dir / f"NEWS-PHP-{b}") if news_dir else None
        text = None
        if not offline:
            try:
                text = _get(f"{RAW}/php/php-src/PHP-{b}/NEWS").decode("utf-8", "replace")
                if news_dir:
                    news_dir.mkdir(parents=True, exist_ok=True)
                    local.write_text(text)
            except Exception as ex:
                print(f"  fetch {b} failed ({ex}); using cache", file=sys.stderr)
        if text is None:
            if local and local.exists():
                text = local.read_text(errors="replace")
            else:
                print(f"  skip {b}: no NEWS available", file=sys.stderr)
                continue
        n = 0
        for version, date, section, txt in parse_news(text):
            if not version.startswith(b + "."):
                continue          # a branch NEWS also carries older branches' history
            m = _CVE_PARENS.search(txt)
            if not m:
                continue
            for cve in re.split(r"\s*,\s*", m.group(1)):
                e = out.setdefault(cve, {"branches": {}, "dates": {}, "sections": set(), "texts": [], "ghsa": set()})
                cur = e["branches"].get(b)
                if cur is None or _vt(version) < _vt(cur):
                    e["branches"][b] = version
                    e["dates"][b] = date
                    e.setdefault("unreleased", set())
                    (e["unreleased"].add if date is None else e["unreleased"].discard)(b)
                e["sections"].add(section or "Core")
                e["texts"].append(txt)
                e["ghsa"].update(_GHSA.findall(txt))
                n += 1
        print(f"  {b}: {n} CVE-tagged fixes", file=sys.stderr)
    return out


def nvd_path(cve: str) -> str:
    y, n = cve.split("-")[1], cve.split("-")[2]
    return f"CVE-{y}/CVE-{y}-{n[:-2]}xx/{cve}.json"


def fetch_nvd(cve: str, nvd_dir: Path | None, offline: bool):
    local = (nvd_dir / f"{cve}.json") if nvd_dir else None
    if local and local.exists():
        return json.loads(local.read_text())
    if offline:
        return None
    try:
        raw = _get(f"{RAW}/fkie-cad/nvd-json-data-feeds/main/{nvd_path(cve)}")
    except Exception as ex:     # 404 for very new CVEs, network blips
        print(f"  nvd miss {cve}: {ex}", file=sys.stderr)
        return None
    if nvd_dir:
        nvd_dir.mkdir(parents=True, exist_ok=True)
        local.write_bytes(raw)
    return json.loads(raw)


def nvd_fields(d: dict | None) -> dict:
    if not d:
        return {}
    out = {"published": (d.get("published") or "")[:10]}
    desc = next((x["value"] for x in d.get("descriptions", []) if x.get("lang") == "en"), "")
    out["description"] = desc
    metrics = d.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            cd = m.get("cvssData", {})
            score = cd.get("baseScore")
            sev = (cd.get("baseSeverity") or m.get("baseSeverity") or "").lower()
            if score is not None:
                out["cvss"] = float(score)
                out["severity"] = sev or _sev_from_score(float(score))
                break
        if "cvss" in out:
            break
    out["references"] = [r["url"] for r in d.get("references", [])][:8]
    return out


def _sev_from_score(s: float) -> str:
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "unknown"


_SAPI_WORDS = {
    "fpm": re.compile(r"\bphp-?fpm\b|\bfpm\b", re.I),
    "cgi": re.compile(r"\bphp-?cgi\b|\bcgi\b", re.I),
    "cli": re.compile(r"\bphp-?cli\b|\bcli\b(?! server)", re.I),
}
_WIN = re.compile(r"\bwindows\b|\bwin32\b|\bwin64\b", re.I)


def classify(cve: str, e: dict, nvd: dict):
    text = " ".join(e["texts"]) + " " + nvd.get("description", "")
    sections = {s.lower() for s in e["sections"]}
    # SAPI: only narrow when NEWS files the fix under that SAPI's section, or the
    # description names it as the affected component.
    sapi = ["any"]
    if "cgi" in sections or _SAPI_WORDS["cgi"].search(text):
        sapi = ["cgi"]
    if "fpm" in sections or _SAPI_WORDS["fpm"].search(text):
        sapi = ["fpm"] if sapi == ["any"] else sorted(set(sapi + ["fpm"]))
    os_ = ["windows"] if _WIN.search(text) else ["any"]
    t = text.lower()
    if re.search(r"remote code execution|arbitrary code|\brce\b|argument injection|command injection", t):
        kind = "rce"
    elif re.search(r"use-after-free|use after free|buffer overflow|out-of-bounds write|heap overflow|stack overflow|double free|integer overflow", t):
        kind = "memory-corruption"
    elif re.search(r"bypass", t):
        kind = "bypass"
    elif re.search(r"out-of-bounds read|disclosure|leak|read beyond|uninitiali[sz]ed", t):
        kind = "info-disclosure"
    elif re.search(r"denial of service|\bdos\b|infinite loop|stack exhaustion|crash|segfault|null pointer", t):
        kind = "dos"
    elif re.search(r"injection|smuggling|crlf", t):
        kind = "injection"
    else:
        kind = "vuln"
    comp = sorted(sections)[0].replace(" ", "-") if sections else "core"
    return sapi, os_, f"{comp}-{kind}"


def title_for(e: dict, nvd: dict) -> str:
    """NEWS wording first ("Fixed bug GHSA-x (Title). (CVE) (author)"), NVD fallback."""
    for txt in e["texts"]:
        # the author credit is the LAST parenthetical of a NEWS bullet; never use it as a title
        parens = re.findall(r"\(((?:[^()]|\([^()]*\))+)\)", txt)
        credit = parens[-1].strip() if len(parens) > 1 else None
        m = re.search(r"(?:GHSA-[0-9a-z-]+|GH-\d+|bug #\d+)[^(]*\(((?:[^()]|\([^()]*\))+)\)", txt)
        cand = m.group(1).strip() if m else ""
        if cand and not cand.startswith("CVE-") and len(cand) > 12 and cand != credit:
            return cand.rstrip(".")[:160]
    desc = nvd.get("description", "")
    if desc:
        first = re.split(r"(?<=[.!?])\s", desc.strip())[0]
        return first[:160].rstrip(".")
    txt = re.sub(r"^Fixed (bug )?", "", e["texts"][0])
    txt = _CVE_PARENS.sub("", txt)
    txt = re.sub(r"\s*\([^()]*\)\s*$", "", txt)       # trailing author credit
    return txt.strip(" .")[:160]


def build_entry(cve: str, e: dict, nvd: dict, latest_branches: list) -> dict:
    sapi, os_, cls = classify(cve, e, nvd)
    branches = {b: ({"fixed": v, "released": False} if b in e.get("unreleased", set()) else {"fixed": v})
                for b, v in sorted(e["branches"].items(), key=lambda kv: _vt(kv[0]))}
    fixed_list = [branches[b]["fixed"] + ("" if branches[b].get("released", True) else " (unreleased)")
                  for b in sorted(branches, key=_vt, reverse=True)]
    oldest_fixed = min(branches, key=_vt)
    # A branch older than the oldest fixed one had no fix shipped: treat as
    # affected unless that branch was already EOL before the bug was introduced.
    # NEWS cannot tell us introduction dates, so stay conservative: affected.
    published = nvd.get("published") or min(d for d in e["dates"].values() if d) if any(e["dates"].values()) else ""
    cvss = nvd.get("cvss", 0.0)
    return {
        "id": cve,
        "aka": sorted(e["ghsa"]),
        "title": title_for(e, nvd),
        "class": cls,
        "cvss": cvss,
        "severity": nvd.get("severity") or "unknown",
        "published": published,
        "exploited_in_wild": False,
        "sapi": sapi,
        "os": os_,
        "branches": branches,
        "eol_affected": eol_affected_for(e["branches"], e["dates"]),
        "exposure": [],
        "detectors": [],
        "remediation": "Upgrade to " + " / ".join(fixed_list)
                       + (f". Branches older than {oldest_fixed} received no fix (end-of-life)."
                          if eol_affected_for(e["branches"], e["dates"])
                          else (f". Branches older than {oldest_fixed} are not affected."
                                if oldest_fixed != ALL_BRANCHES[0] else ".")),
        "references": nvd.get("references") or [f"https://www.php.net/ChangeLog-{oldest_fixed[0]}.php"],
        "description": nvd.get("description", ""),
        "source": "php-src NEWS" + (" + NVD" if nvd else ""),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--branches", nargs="*", default=DEFAULT_BRANCHES)
    ap.add_argument("--news-dir", type=Path, default=None, help="cache dir for NEWS files")
    ap.add_argument("--nvd-dir", type=Path, default=None, help="cache dir for NVD json")
    ap.add_argument("--min-year", type=int, default=2016)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()

    print("parsing php-src NEWS …", file=sys.stderr)
    found = collect(a.branches, a.news_dir, a.offline)
    cves = sorted(c for c in found if int(c.split("-")[1]) >= a.min_year)
    print(f"{len(cves)} CVEs ≥ {a.min_year}; fetching NVD …", file=sys.stderr)
    with cf.ThreadPoolExecutor(a.workers) as ex:
        nvd = dict(zip(cves, ex.map(lambda c: nvd_fields(fetch_nvd(c, a.nvd_dir, a.offline)), cves)))
    entries = [build_entry(c, found[c], nvd[c], a.branches) for c in cves]
    entries.sort(key=lambda e: e["published"], reverse=True)
    Path(a.out).write_text(json.dumps({"cves": entries}, indent=1) + "\n")
    with_nvd = sum(1 for c in cves if nvd[c])
    print(f"wrote {len(entries)} entries ({with_nvd} with NVD metrics) -> {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
