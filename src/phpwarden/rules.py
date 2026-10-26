"""Generate WAF blocking rules from the feed's request signatures.

phpwarden does not replace an edge WAF; it supplies the PHP-specific rules a
generic WAF lacks, in the formats real WAFs enforce (ModSecurity, nginx). The
same signatures power `phpwarden detect` (observe) and these rules (block).
"""
from __future__ import annotations

import re
from typing import List

from phpwarden.vulndb import Feed

RULE_ID_BASE = 9100000


def _request_sigs(feed: Feed):
    """[(cve_id, pattern, note), ...] for request-signature detectors only."""
    out, seen = [], set()
    for cve in feed.cves:
        for det in cve.detectors:
            if det.get("kind") != "request-signature":
                continue
            for pat in det.get("patterns", []):
                key = (cve.id, pat.lower())
                if key not in seen:
                    seen.add(key)
                    out.append((cve.id, pat, det.get("note", "")))
    return out


def _modsec_lines(entries, rid_base=RULE_ID_BASE):
    """entries: [(cve_id, pattern, note), ...] -> ModSecurity SecRule lines."""
    out, rid = [], rid_base
    for cve_id, pat, note in entries:
        rx = re.escape(pat)
        # (?i): @rx is case-sensitive and real probes use "%AD"/"%0A"; the
        # signature list is de-duplicated case-insensitively, so without this
        # the upper-case variants were simply never blocked.
        # REQUEST_URI_RAW: ARGS/REQUEST_URI are URL-decoded by the engine, so a
        # percent-encoded pattern can only ever match the raw URI.
        safe_note = note.replace("'", "`").replace('"', "`")
        out.append(
            f'SecRule REQUEST_URI_RAW|REQUEST_URI|REQUEST_HEADERS:Content-Type|ARGS '
            f'"@rx (?i){rx}" '
            f'"id:{rid},phase:2,deny,status:403,'
            f'msg:\'phpwarden: {cve_id} exploitation signature\','
            f'logdata:\'{safe_note}\',tag:\'phpwarden\',tag:\'{cve_id}\'"')
        rid += 1
    return out


def _nginx_lines(entries):
    out = []
    for cve_id, pat, note in entries:
        rx = re.escape(pat)
        out.append(f'# {cve_id}: {note}')
        out.append(f'if ($request_uri ~* "{rx}") {{ return 403; }}')
    return out


def modsecurity(feed: Feed) -> str:
    lines = [
        "# phpwarden-generated ModSecurity rules — PHP exploitation signatures.",
        f"# feed {feed.feed_version}. Place in your CRS custom rules; tune IDs to avoid clashes.",
        "",
    ]
    lines += _modsec_lines(_request_sigs(feed))
    lines.append("")
    return "\n".join(lines)


def nginx(feed: Feed) -> str:
    lines = [
        "# phpwarden-generated nginx rules — PHP exploitation signatures.",
        f"# feed {feed.feed_version}. Include inside the server/location that proxies to PHP-FPM.",
        "",
    ]
    lines += _nginx_lines(_request_sigs(feed))
    lines.append("")
    return "\n".join(lines)


FORMATS = {"modsecurity": modsecurity, "nginx": nginx}


def generate(feed: Feed, fmt: str) -> str:
    gen = FORMATS.get(fmt)
    if not gen:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    return gen(feed)


# --- per-CVE virtual patch ("shields-up") ---------------------------------- #
# Contain a single CVE *before* you can upgrade. The blocking rule is built from
# (1) the feed's authoritative request-signature for that CVE, and (2) patterns
# we actually observed probing this host (the attack log) — so the shield blocks
# exactly what is being thrown at you. When neither exists, we emit a runtime
# guard policy that recycles a poisoned PHP-FPM worker for that CVE instead.

def _cve_entries(feed: Feed, cve_id: str, observed=None):
    """Blocking entries for one CVE: feed signatures + observed attack patterns."""
    entries, seen = [], set()
    for cid, pat, note in _request_sigs(feed):
        if cid == cve_id and pat.lower() not in seen:
            seen.add(pat.lower())
            entries.append((cid, pat, note or "feed exploitation signature"))
    for pat in (observed or []):
        if pat and pat.lower() not in seen:
            seen.add(pat.lower())
            entries.append((cve_id, pat, "observed in your logs"))
    return entries


def guard_policy(cve_id: str) -> str:
    """A phpwarden runtime-guard policy fragment that enforces (recycles a
    poisoned PHP-FPM worker) for this CVE — the containment layer a WAF can't do."""
    return (
        "# phpwarden runtime guard — enforce containment for this CVE.\n"
        "# Add to your guard config and run the guard in ENFORCE mode:\n"
        "#   phpwarden-guard --config guard.json --mode ENFORCE\n"
        "{\n"
        '  "mode": "ENFORCE",\n'
        f'  "enforce_cves": ["{cve_id}"],\n'
        '  "action": "recycle_worker"\n'
        "}\n"
    )


def virtual_patch(feed: Feed, cve_id: str, fmt: str = "nginx", observed=None) -> dict:
    """Build a one-CVE virtual patch. Returns {text, has_waf, kind}."""
    entries = _cve_entries(feed, cve_id, observed)
    header = [
        f"# phpwarden virtual patch — {cve_id}",
        f"# feed {feed.feed_version}. Contain this CVE now; remove once you've upgraded.",
        "",
    ]
    if entries:
        body = _nginx_lines(entries) if fmt == "nginx" else _modsec_lines(entries)
        where = ("Include inside the server/location that proxies to PHP-FPM."
                 if fmt == "nginx" else "Place in your CRS custom rules; tune IDs to avoid clashes.")
        text = "\n".join(header + [f"# {where}", ""] + body + ["",
               "# Runtime containment (defense in depth):", ""] + guard_policy(cve_id).splitlines())
        return {"text": text + "\n", "has_waf": True, "kind": fmt}
    # no signature and nothing observed yet -> guard policy only
    text = "\n".join(header + [
        "# No request-signature is available for this CVE, and nothing matching it",
        "# has been seen in your logs yet, so an edge WAF rule can't target it precisely.",
        "# Contain it at runtime instead — the guard recycles a poisoned PHP-FPM worker:",
        "",
    ] + guard_policy(cve_id).splitlines())
    return {"text": text + "\n", "has_waf": False, "kind": "guard"}
