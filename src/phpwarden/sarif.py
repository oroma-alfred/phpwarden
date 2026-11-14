"""SARIF 2.1.0 output for the CLI (`--format sarif`).

One converter per command, each taking the same document `--json` prints, so the
two formats can never disagree. SARIF is what GitHub code scanning, GitLab
(via its SARIF importer), Azure DevOps and most CI dashboards read.

Level mapping: known-exploited (KEV) or EPSS >= 50% is always "error", whatever
the CVSS; then critical/high -> error, medium -> warning, everything else note.
"""
from __future__ import annotations

from phpwarden import __version__

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://phpwarden.io"


def level(severity, known_exploited=False, epss=None) -> str:
    if known_exploited or (isinstance(epss, (int, float)) and epss >= 0.5):
        return "error"
    sev = str(severity or "").lower()
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    return "note"


def _doc(results, rules, tool="phpwarden"):
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": tool, "version": __version__, "informationUri": INFO_URI,
                            "rules": list(rules.values())}},
        "results": results}]}


def _rule(rules, rid, title, help_uri=None, exploited=False, cvss=None):
    if rid not in rules:
        r = {"id": rid, "shortDescription": {"text": (title or rid)[:240]},
             "properties": {"tags": ["security"] + (["known-exploited"] if exploited else [])}}
        if help_uri:
            r["helpUri"] = help_uri
        if isinstance(cvss, (int, float)) and cvss > 0:
            r["properties"]["security-severity"] = f"{cvss:.1f}"   # GitHub reads this
        rules[rid] = r
    return rid


def _help(cve):
    return f"https://phpwarden.io/advisories/{cve}" if str(cve or "").startswith("CVE-") else None


def _tags(known, epss, ransomware=False):
    t = []
    if known:
        t.append("KEV")
    if ransomware:
        t.append("ransomware")
    if isinstance(epss, (int, float)):
        t.append(f"EPSS {epss * 100:.0f}%")
    return f" [{', '.join(t)}]" if t else ""


def _result(rid, lvl, text, uri, line=1, props=None):
    res = {"ruleId": rid, "level": lvl, "message": {"text": text},
           "locations": [{"physicalLocation": {
               "artifactLocation": {"uri": uri}, "region": {"startLine": max(1, int(line or 1))}}}]}
    if props:
        res["properties"] = props
    return res


def _lock_lines(lock_text: str) -> dict:
    """package name -> 1-based line of its `"name": "<pkg>"` entry."""
    out = {}
    for i, ln in enumerate(lock_text.splitlines(), 1):
        s = ln.strip()
        if s.startswith('"name":'):
            name = s.split(":", 1)[1].strip().strip(",").strip('"')
            out.setdefault(name, i)
    return out


def deps(doc: dict, lock_text: str = "") -> dict:
    lines, rules, results = _lock_lines(lock_text), {}, []
    for v in doc.get("vulnerable", []):
        rid = v.get("cve") or f"{v['package']}-advisory"
        _rule(rules, rid, v.get("title"), _help(v.get("cve")), v.get("known_exploited"), v.get("cvss"))
        fixed = ", ".join(v.get("fixed") or []) or "no fixed version published"
        text = (f"{v['package']} {v['installed']}: {v.get('title') or rid}"
                f"{_tags(v.get('known_exploited'), v.get('epss'), v.get('ransomware'))}. Fixed in: {fixed}.")
        results.append(_result(rid, level(v.get("severity"), v.get("known_exploited"), v.get("epss")),
                               text, doc.get("lockfile", "composer.lock"), lines.get(v["package"], 1),
                               {"package": v["package"], "installed": v["installed"],
                                "known_exploited": bool(v.get("known_exploited")),
                                "epss": v.get("epss"), "reach": v.get("reach")}))
    return _doc(results, rules)


def wordpress(doc: dict) -> dict:
    rules, results = {}, []
    root = str(doc.get("wordpress", ".")).rstrip("/")
    for f in doc.get("findings", []):
        rid = f.get("cve") or f"{f['slug']}-advisory"
        _rule(rules, rid, f.get("title"), _help(f.get("cve")), f.get("known_exploited"), f.get("cvss"))
        where = {"core": "wp-includes/version.php", "plugin": f"wp-content/plugins/{f['slug']}",
                 "theme": f"wp-content/themes/{f['slug']}"}.get(f.get("kind"), f["slug"])
        fixed = ", ".join(f.get("fixed") or []) or "no fixed version published"
        text = (f"{f.get('kind')} {f['slug']} {f.get('version')}: {f.get('title') or rid}"
                f"{_tags(f.get('known_exploited'), f.get('epss'), f.get('ransomware'))}. Fixed in: {fixed}.")
        results.append(_result(rid, level(f.get("severity"), f.get("known_exploited"), f.get("epss")),
                               text, f"{root}/{where}", 1,
                               {"slug": f["slug"], "version": f.get("version"),
                                "known_exploited": bool(f.get("known_exploited")), "epss": f.get("epss")}))
    return _doc(results, rules)


def scan(doc: dict) -> dict:
    """Engine findings have no file; they are attached to the PHP runtime."""
    rules, results = {}, []
    uri = f"php-{doc.get('php_version') or 'unknown'}"
    for f in doc.get("findings", []):
        rid = f["cve"]
        _rule(rules, rid, f.get("title"), _help(rid), f.get("exploited_in_wild"), f.get("cvss"))
        lvl = level(f.get("severity"), f.get("exploited_in_wild"), f.get("epss"))
        if f.get("verdict") == "POSSIBLY_EXPOSED" and lvl == "error" and not f.get("exploited_in_wild"):
            lvl = "warning"
        text = (f"PHP {doc.get('php_version') or '?'} ({doc.get('sapi') or '?'}): {f.get('title')}"
                f"{_tags(f.get('exploited_in_wild'), f.get('epss'), f.get('ransomware'))}. "
                f"{'Exposed' if f.get('verdict') == 'EXPOSED' else 'Possibly exposed'}. "
                f"Fix: {f.get('remediation') or f.get('fixed') or 'upgrade PHP'}")
        results.append(_result(rid, lvl, text, uri, 1,
                               {"verdict": f.get("verdict"), "known_exploited": bool(f.get("exploited_in_wild")),
                                "epss": f.get("epss")}))
    return _doc(results, rules)
