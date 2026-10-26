"""Exposure engine: assess a PHP environment against the whole CVE feed.

This is the deterministic backbone — given what we know about a host (PHP
version, which SAPI, OS, and any confirmed config facts), it returns one finding
per applicable CVE with a calibrated confidence. It never guesses a version is
safe: unknowns stay unknown.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set

from phpwarden import version as V
from phpwarden.vulndb import CVE, Feed


@dataclass
class Environment:
    version: Optional[V.Version] = None
    sapi: Optional[str] = None            # "fpm" | "cgi" | "cli" | None(unknown)
    os: Optional[str] = None              # "linux" | "windows" | None(unknown)
    arch: Optional[str] = None            # "32" | "64" | None
    config_true: Set[str] = field(default_factory=set)   # confirmed-true exposure checks

    @classmethod
    def from_version_string(cls, text, **kw):
        return cls(version=V.parse(text), **kw)


@dataclass
class Finding:
    cve: CVE
    verdict: str            # EXPOSED | POSSIBLY_EXPOSED | CLEARED
    confidence: str         # high | medium | low
    reasons: List[str]
    fixed: Optional[str]

    @property
    def exposed(self):
        return self.verdict in ("EXPOSED", "POSSIBLY_EXPOSED")


def _sapi_match(cve: CVE, env: Environment):
    """(matches, confident). 'any' always matches with confidence."""
    if cve.sapi == ["any"]:
        return True, True
    if env.sapi is None:
        return True, False          # could match; we can't confirm
    return (env.sapi in cve.sapi), True


def _os_match(cve: CVE, env: Environment):
    if cve.os == ["any"]:
        return True, True
    if env.os is None:
        return True, False
    return (env.os in cve.os), True


def assess_one(cve: CVE, env: Environment) -> Finding:
    fixed = cve.fixed_for(env.version) if env.version else None
    if env.version is None:
        # Version unknown — but a CVE that needs a SAPI or OS we KNOW this host
        # doesn't have is still ruled out (a Windows/CGI-only bug on linux/cli).
        sapi_ok, sapi_conf = _sapi_match(cve, env)
        os_ok, os_conf = _os_match(cve, env)
        if (sapi_conf and not sapi_ok) or (os_conf and not os_ok):
            why = ("SAPI not in the vulnerable set" if (sapi_conf and not sapi_ok)
                   else "OS not in the vulnerable set")
            return Finding(cve, "CLEARED", "medium", [why + " (PHP version unknown)"], fixed)
        return Finding(cve, "POSSIBLY_EXPOSED", "low",
                       ["PHP version unknown; cannot rule this out"], fixed)

    vs = cve.version_status(env.version)
    if vs in ("PATCHED", "NOT_APPLICABLE"):
        reason = ("at or above the fixed release on this branch" if vs == "PATCHED"
                  else "this PHP branch is not in the vulnerable set")
        return Finding(cve, "CLEARED", "high", [reason], fixed)

    reasons = []
    if vs == "EOL_AFFECTED":
        reasons.append("PHP branch is end-of-life with no upstream fix for this CVE")
    else:
        reasons.append(f"version is below the fixed release {fixed} on this branch")

    sapi_ok, sapi_conf = _sapi_match(cve, env)
    os_ok, os_conf = _os_match(cve, env)
    if not sapi_ok:
        return Finding(cve, "CLEARED", "high",
                       [f"this CVE affects only {'/'.join(cve.sapi)} SAPI; host runs {env.sapi}"], fixed)
    if not os_ok:
        return Finding(cve, "CLEARED", "high",
                       [f"this CVE affects only {'/'.join(cve.os)}; host runs {env.os}"], fixed)

    confident = sapi_conf and os_conf
    if cve.sapi != ["any"] and not sapi_conf:
        reasons.append(f"applies only to {'/'.join(cve.sapi)} SAPI (not confirmed on this host)")
    if cve.os != ["any"] and not os_conf:
        reasons.append(f"applies only on {'/'.join(cve.os)} (not confirmed on this host)")

    # Config-gated CVEs: note unconfirmed conditions, downgrade confidence.
    unconfirmed_conf = [c for c in cve.exposure if c.get("check") not in env.config_true]
    if unconfirmed_conf:
        for c in unconfirmed_conf:
            reasons.append("conditional: " + c.get("desc", c.get("check", "")))

    if confident and not unconfirmed_conf:
        return Finding(cve, "EXPOSED", "high", reasons, fixed)
    verdict = "POSSIBLY_EXPOSED"
    conf = "medium" if confident or not unconfirmed_conf else "low"
    return Finding(cve, verdict, conf, reasons, fixed)


def assess(env: Environment, feed: Feed) -> List[Finding]:
    """Assess every CVE; return findings sorted worst-first."""
    findings = [assess_one(c, env) for c in feed.cves]
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    verd = {"EXPOSED": 0, "POSSIBLY_EXPOSED": 1, "CLEARED": 2}
    findings.sort(key=lambda f: (
        verd[f.verdict],
        0 if f.cve.exploited_in_wild else 1,
        -(f.cve.epss or 0),
        sev.get(f.cve.severity, 9), -f.cve.cvss))
    return findings


def summarize(findings: List[Finding]) -> dict:
    exposed = [f for f in findings if f.verdict == "EXPOSED"]
    possible = [f for f in findings if f.verdict == "POSSIBLY_EXPOSED"]
    return {
        "exposed": len(exposed),
        "possibly_exposed": len(possible),
        "cleared": sum(1 for f in findings if f.verdict == "CLEARED"),
        "worst_severity": exposed[0].cve.severity if exposed else (
            possible[0].cve.severity if possible else "none"),
        "exploited_in_wild": sorted({f.cve.id for f in exposed + possible if f.cve.exploited_in_wild}),
    }
