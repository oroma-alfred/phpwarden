"""Read Trivy JSON (npm/JS, OS packages, container images, IaC) into phpwarden.

phpwarden covers PHP: the engine, Composer, WordPress and your own PHP code.
The rest of what a PHP project ships (package-lock.json, the container image,
the Dockerfile and Terraform next to it) is Trivy's job, and Trivy does it well.
So phpwarden does not reimplement it: it reads the JSON Trivy writes

    trivy fs     --format json --output trivy.json .
    trivy image  --format json --output trivy.json IMAGE
    trivy config --format json --output trivy.json .

and puts those findings in the same ranked report, ordered the same way as PHP
ones: CISA KEV first, then EPSS, then severity. KEV and EPSS for non-PHP CVEs
come from files you pass (`kev`, `epss`): the CISA catalogue JSON and the FIRST
EPSS CSV. Without them findings are ranked by severity, and the report says so.

Secrets that Trivy finds are reported by rule and file only. The matched text
(`Match`, `Code`) is never read into a finding, stored or printed.

Composer results inside a Trivy report are skipped: phpwarden's own `deps`
already covers composer.lock with reachability, and counting both would
double every PHP finding.

Stdlib only. Schema: Trivy JSON report, SchemaVersion 2.
"""
from __future__ import annotations

import csv
import gzip
import json
import shutil
import subprocess
from pathlib import Path

_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "unknown"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
SKIP_TYPES = {"composer"}          # PHP dependencies: phpwarden's own `deps` owns them
EPSS_HOT = 0.5


class TrivyError(ValueError):
    pass


def load_report(path) -> dict:
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise TrivyError(f"cannot read Trivy report {path}: {e}") from e
    if not isinstance(doc, dict) or "Results" not in doc and "SchemaVersion" not in doc:
        raise TrivyError(f"{path} is not a Trivy JSON report (no SchemaVersion/Results)")
    sv = doc.get("SchemaVersion")
    if sv not in (None, 2):
        raise TrivyError(f"{path}: Trivy SchemaVersion {sv} is not supported (expected 2)")
    return doc


def load_kev(path) -> set:
    if not path:
        return set()
    doc = json.loads(Path(path).read_text())
    return {v.get("cveID") for v in doc.get("vulnerabilities", []) if v.get("cveID")}


def load_epss(path) -> dict:
    if not path:
        return {}
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" else open
    out = {}
    with opener(p, "rt", newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or row[0] == "cve":
                continue
            try:
                out[row[0]] = float(row[1])
            except (ValueError, IndexError):
                continue
    return out


def _cvss(v) -> float:
    best = 0.0
    for src in (v.get("CVSS") or {}).values():
        for k in ("V3Score", "V2Score"):
            try:
                best = max(best, float(src.get(k) or 0))
            except (TypeError, ValueError):
                pass
    return best


def _dev_ids(result) -> set:
    """Package ids Trivy marked as development-only (npm devDependencies)."""
    return {p.get("ID") for p in (result.get("Packages") or []) if p.get("Dev") and p.get("ID")}


def findings(doc: dict, kev=frozenset(), epss=None) -> list:
    """Flatten a Trivy report into phpwarden-style finding dicts."""
    epss = epss or {}
    out = []
    artifact = doc.get("ArtifactName") or ""
    for r in doc.get("Results") or []:
        rtype = (r.get("Type") or "").lower()
        target = r.get("Target") or artifact
        if rtype in SKIP_TYPES:
            continue
        dev = _dev_ids(r)
        for v in r.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or ""
            cve = vid if vid.startswith("CVE-") else None
            pid = (v.get("PkgIdentifier") or {}).get("UID") or v.get("PkgID")
            is_dev = bool(v.get("Dev")) or (pid in dev if pid else False) or (v.get("PkgID") in dev)
            out.append({
                "kind": "trivy-vuln", "class": r.get("Class") or "", "type": rtype, "target": target,
                "package": v.get("PkgName") or "", "installed": v.get("InstalledVersion") or "",
                "id": vid, "cve": cve, "title": (v.get("Title") or vid)[:300],
                "severity": _SEV.get((v.get("Severity") or "").upper(), "unknown"),
                "cvss": _cvss(v), "fixed": [x.strip() for x in (v.get("FixedVersion") or "").split(",") if x.strip()],
                "url": v.get("PrimaryURL") or "",
                "known_exploited": bool(cve and cve in kev), "epss": epss.get(cve) if cve else None,
                "dev": is_dev,
            })
        for m in r.get("Misconfigurations") or []:
            if (m.get("Status") or "FAIL").upper() != "FAIL":
                continue
            out.append({
                "kind": "trivy-misconfig", "class": "config", "type": rtype, "target": target,
                "package": target, "installed": "", "id": m.get("AVDID") or m.get("ID") or "",
                "cve": None, "title": (m.get("Title") or m.get("ID") or "")[:300],
                "severity": _SEV.get((m.get("Severity") or "").upper(), "unknown"), "cvss": 0.0,
                "fixed": [], "fix": (m.get("Resolution") or "")[:300], "url": m.get("PrimaryURL") or "",
                "known_exploited": False, "epss": None, "dev": False,
            })
        for s in r.get("Secrets") or []:
            # never copy Match / Code: they hold the secret itself
            out.append({
                "kind": "trivy-secret", "class": "secret", "type": rtype, "target": target,
                "package": target, "installed": "", "id": s.get("RuleID") or "secret",
                "cve": None, "title": (s.get("Title") or s.get("RuleID") or "secret")[:200],
                "severity": _SEV.get((s.get("Severity") or "").upper(), "unknown"), "cvss": 0.0,
                "fixed": [], "fix": "Remove the secret from the file and rotate it.",
                "line": s.get("StartLine"), "url": "", "known_exploited": False, "epss": None, "dev": False,
            })
    out.sort(key=rank_key)
    return out


def rank_key(f):
    return (0 if f["known_exploited"] else 1, -(f.get("epss") or 0), _SEV_RANK.get(f["severity"], 4),
            -(f.get("cvss") or 0), f["target"], f["package"], f["id"])


def ident(f) -> str:
    """Dashboard identifier. For vulnerabilities, "pkg ver / CVE" like Composer
    findings, so exploited-CVE alerts match them by CVE id."""
    if f["kind"] == "trivy-vuln":
        return f"{f['package']} {f['installed']} / {f['cve'] or f['id']}"
    return f"{f['target']} / {f['id']}"


def to_report_doc(fs, source_files=()) -> dict:
    """The JSON uploaded to the dashboard (--report-to)."""
    return {"tool": "phpwarden-trivy-import", "trivy": [
        {"ident": ident(f), "kind": f["kind"], "severity": f["severity"], "cvss": f.get("cvss") or 0,
         "epss": f.get("epss"), "known_exploited": f["known_exploited"], "title": f["title"],
         "fixed": ", ".join(f["fixed"]) or "-", "dev": f["dev"]} for f in fs],
        "files": [str(p) for p in source_files]}


def run_trivy_fs(path, timeout=600):
    """Run `trivy fs` on `path` if the binary is installed. Never downloads it.
    Returns (doc, None) or (None, message)."""
    exe = shutil.which("trivy")
    if not exe:
        return None, ("trivy is not installed, so the non-PHP view was skipped. Install it "
                      "(https://trivy.dev) or pass a saved report with --trivy FILE.")
    try:
        p = subprocess.run([exe, "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig,secret",
                            str(path)], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"trivy failed to run: {e.__class__.__name__}"
    if p.returncode not in (0, 1):
        return None, f"trivy exited {p.returncode}: {p.stderr.strip()[:200]}"
    try:
        return json.loads(p.stdout), None
    except ValueError:
        return None, "trivy did not print a JSON report"
