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


_PCT_BYTE = re.compile(r"^%[0-9a-f]{2}$")
_WORD = re.compile(r"^[a-z_][a-z0-9_]*$")


def signature_regex(pat: str) -> str:
    """The regex (case-insensitive, applied to the RAW request URI: path and
    query, still percent-encoded) that enforces one feed signature.

    It mirrors what `phpwarden detect` treats as a hit, so that blocking rules,
    `--dry-run` rules and `--replay` all agree, and ordinary traffic is not
    blocked:

      * a control byte such as %0a counts only in the path (a newline inside a
        form field or a search query is normal);
      * a high byte such as %ad counts only when it is not part of a valid
        UTF-8 sequence ("categor%C3%ADa" is the word categoría, not the
        soft-hyphen injection);
      * a php.ini directive name counts only when it is being assigned
        (`auto_prepend_file=`), not when it merely appears in a URL or a
        search; an encoded underscore (%5f) is accepted.
    """
    p = pat.lower()
    if _PCT_BYTE.match(p):
        byte = int(p[1:], 16)
        if byte < 0x20:
            return r"^[^?]*" + re.escape(p)
        if 0x80 <= byte <= 0xbf:            # continuation byte: valid only after another high byte
            return r"(?<!%[89a-f][0-9a-f])" + re.escape(p)
        if byte >= 0xc0:                    # lead byte: valid only when a continuation byte follows
            return re.escape(p) + r"(?!%[89ab][0-9a-f])"
        return re.escape(p)
    if _WORD.match(p):
        return re.escape(p).replace("_", "(?:_|%5f)") + r"\s*(?:=|%3d)"
    return re.escape(p)


def _modsec_lines(entries, rid_base=RULE_ID_BASE, dry_run=False):
    """entries: [(cve_id, pattern, note), ...] -> ModSecurity SecRule lines.

    dry_run: the rule logs the match (error log + audit log) and lets the
    request through, so you can see what would be blocked before enforcing."""
    action = "pass,log,auditlog" if dry_run else "deny,status:403"
    label = "phpwarden DRY-RUN (would block)" if dry_run else "phpwarden"
    out, rid = [], rid_base
    for cve_id, pat, note in entries:
        rx = signature_regex(pat)
        # (?i): @rx is case-sensitive and real probes use "%AD"/"%0A".
        # REQUEST_URI_RAW only: the signatures are written against the raw,
        # still-encoded request line. The decoded variables (REQUEST_URI, ARGS)
        # cannot tell "%C3%AD" (the letter í) from a bare "%AD", and matching
        # them is what used to block ordinary non-English URLs.
        safe_note = note.replace("'", "`").replace('"', "`")
        out.append(
            f'SecRule REQUEST_URI_RAW '
            f'"@rx (?i){rx}" '
            f'"id:{rid},phase:2,{action},'
            f'msg:\'{label}: {cve_id} exploitation signature\','
            f'logdata:\'{safe_note}\',tag:\'phpwarden\',tag:\'{cve_id}\'"')
        rid += 1
    return out


def _nginx_lines(entries, dry_run=False):
    out = []
    for cve_id, pat, note in entries:
        rx = signature_regex(pat)
        out.append(f'# {cve_id}: {note}')
        if dry_run:
            out.append(f'if ($request_uri ~* "{rx}") {{ set $phpwarden_would_block "{cve_id}"; }}')
        else:
            out.append(f'if ($request_uri ~* "{rx}") {{ return 403; }}')
    return out


_DRY_MODSEC = [
    "# DRY-RUN: these rules log and let the request through. Nothing is blocked.",
    "# Matches appear in the ModSecurity audit/error log as 'phpwarden DRY-RUN (would block)'.",
    "# Run it for a few days, check for false positives, then regenerate without --dry-run.",
]
_DRY_NGINX = [
    "# DRY-RUN: these rules only set $phpwarden_would_block. Nothing is blocked.",
    "# Log it by adding the variable to your access log format, in the http block:",
    "#   log_format phpwarden '$remote_addr [$time_local] \"$request\" $status would_block=$phpwarden_would_block';",
    "#   access_log /var/log/nginx/phpwarden-dryrun.log phpwarden if=$phpwarden_would_block;",
    "# Or replay an existing log without touching nginx: phpwarden rules --replay ACCESS_LOG",
    "# Check for false positives, then regenerate without --dry-run.",
    'set $phpwarden_would_block "";',
]


def modsecurity(feed: Feed, dry_run: bool = False) -> str:
    lines = [
        "# phpwarden-generated ModSecurity rules — PHP exploitation signatures.",
        f"# feed {feed.feed_version}. Place in your CRS custom rules; tune IDs to avoid clashes.",
    ] + (_DRY_MODSEC if dry_run else []) + [""]
    lines += _modsec_lines(_request_sigs(feed), dry_run=dry_run)
    lines.append("")
    return "\n".join(lines)


def nginx(feed: Feed, dry_run: bool = False) -> str:
    lines = [
        "# phpwarden-generated nginx rules — PHP exploitation signatures.",
        f"# feed {feed.feed_version}. Include inside the server/location that proxies to PHP-FPM.",
    ] + (_DRY_NGINX if dry_run else []) + [""]
    lines += _nginx_lines(_request_sigs(feed), dry_run=dry_run)
    lines.append("")
    return "\n".join(lines)


FORMATS = {"modsecurity": modsecurity, "nginx": nginx}


def generate(feed: Feed, fmt: str, dry_run: bool = False) -> str:
    gen = FORMATS.get(fmt)
    if not gen:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    return gen(feed, dry_run)


def replay(feed: Feed, logfile, top: int = 10) -> dict:
    """What the blocking rules WOULD have done to the traffic in an access log.

    Runs the same request signatures over the log (no web server involved) and
    summarises the requests that would get a 403: per CVE, the most-hit paths
    and client addresses, and how many of those requests the server had
    answered 2xx/3xx. That last number is where false positives hide: a probe
    normally gets a 404 or 403, a real page gets a 200."""
    from collections import Counter
    from phpwarden.detect import _normalize, parse_access_line

    # Evaluate the very regexes the generated rules contain, on the raw request
    # target, so this report and the enforced rules cannot disagree.
    compiled = {}
    for cve_id, pat, _note in _request_sigs(feed):
        compiled.setdefault(cve_id, []).append(re.compile(signature_regex(pat), re.I))
    by_cve, paths, clients, served = Counter(), Counter(), Counter(), Counter()
    samples, lines, blocked_lines = {}, 0, 0
    with open(logfile, "r", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            lines = n
            rec = parse_access_line(line) or {}
            req = rec.get("req") or line.strip()
            parts = req.split(" ")
            target = parts[1] if len(parts) >= 2 and parts[1].startswith("/") else req
            target = _normalize(target)          # servers log raw bytes as \xNN
            hit = [cve for cve, rxs in compiled.items() if any(rx.search(target) for rx in rxs)]
            if not hit:
                continue
            blocked_lines += 1
            status = str(rec.get("status") or "")
            for cve in hit:
                by_cve[cve] += 1
                samples.setdefault(cve, {"line": n, "excerpt": line.strip()[:300]})
                if status[:1] in ("2", "3"):
                    served[cve] += 1
            paths[target.split("?")[0][:120] or "?"] += 1
            if rec.get("ip"):
                clients[rec["ip"]] += 1
    return {"logfile": str(logfile), "feed_version": feed.feed_version,
            "scanned_lines": lines, "would_block": blocked_lines,
            "by_cve": [{"cve": c, "requests": n, "served_2xx_3xx": served.get(c, 0),
                        "sample_line": samples[c]["line"], "sample": samples[c]["excerpt"]}
                       for c, n in by_cve.most_common()],
            "top_paths": [{"path": p, "requests": n} for p, n in paths.most_common(top)],
            "top_clients": [{"ip": i, "requests": n} for i, n in clients.most_common(top)],
            "review": sum(served.values())}


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
