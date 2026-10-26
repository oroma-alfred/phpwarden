"""CVSS helpers for the feed builders (stdlib only).

OSV records carry CVSS vectors but no numeric score, so the importer computes
the CVSS v3.0/v3.1 base score from the vector (the specification's formula) and
maps it to phpwarden's severity buckets. CVSS v4.0 scoring needs the MacroVector
lookup table, which we do not ship; v4-only records fall back to the source's
own severity label (GitHub's database_specific.severity).

Severity buckets (CVSS qualitative rating scale):
  9.0-10.0 critical | 7.0-8.9 high | 4.0-6.9 medium | 0.1-3.9 low
"""
import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}     # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}      # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_V3_HEAD = re.compile(r"^CVSS:3\.([01])/")


def _roundup_31(x: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal value >= x, via integer arithmetic
    so 4.000000001-style float noise does not become 4.1."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def _roundup_30(x: float) -> float:
    return math.ceil(x * 10) / 10.0


def base_score_v3(vector: str):
    """Base score for a CVSS:3.0/3.1 vector string, or None if unparseable."""
    if not vector:
        return None
    m = _V3_HEAD.match(vector.strip())
    if not m:
        return None
    minor = m.group(1)
    metrics = {}
    for part in vector.strip().split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    try:
        changed = metrics["S"] == "C"
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_C if changed else _PR_U)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + exploitability), 10.0) if changed else min(impact + exploitability, 10.0)
    return (_roundup_31 if minor == "1" else _roundup_30)(raw)


def severity_from_score(score) -> str:
    if score is None or score <= 0:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


_LABELS = {"critical": "critical", "high": "high", "moderate": "medium",
           "medium": "medium", "low": "low"}


def severity_from_label(label) -> str:
    return _LABELS.get(str(label or "").strip().lower(), "unknown")


def derive(severities, db_severity=None):
    """(cvss, severity) from an OSV `severity` list plus an optional label.

    Prefers a computed CVSS v3 base score; otherwise the label (covers v4-only
    records); otherwise (0.0, "unknown").
    """
    best = None
    for s in severities or []:
        if str(s.get("type", "")).upper() in ("CVSS_V3",):
            score = base_score_v3(s.get("score", ""))
            if score is not None and (best is None or score > best):
                best = score
    if best is not None and best > 0:
        return best, severity_from_score(best)
    label = severity_from_label(db_severity)
    if label != "unknown":
        return 0.0, label
    return 0.0, "unknown"
