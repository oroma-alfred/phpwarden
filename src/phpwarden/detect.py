"""Signature detection: scan logs for the marks of attempted exploitation.

Each CVE in the feed may carry detectors. This module handles the stateless
ones — request-signature (an exploit marker in an access-log line) and
response-signature (a leak marker in a response). Each detector declares the
stream it applies to ("access" or "response"), so scanning an access log never
fires a response-only signature (which would false-positive on normal logging).

Matching is done against the REQUEST TARGET (path + query) of a parsed
access-log line, not the whole line, so a Referer or User-Agent never triggers
a hit. Three pattern classes are told apart because naive substring matching
flagged ordinary traffic:

  * "%xx" single-byte patterns (e.g. "%ad" for CVE-2024-4577, "%0a" for
    CVE-2019-11043): the percent-decoded bytes of the part they appear in must
    be INVALID UTF-8 (a lone 0xAD) or a control byte in the PATH. The "%ad"
    inside the valid UTF-8 "%C3%AD" ("í") is not an exploit, and "%0A" in a
    search query is form input, not a PATH_INFO injection.
  * bare ini-directive words ("allow_url_include", "auto_prepend_file"): only
    when used as an assignment ("...=" / "...%3d"), which is how the php-cgi
    argument-injection exploits pass them. A blog title or "#allow_url_include"
    anchor in a docs URL is not.
  * anything else ("php://input", "/cgi-bin/..."): plain substring.

Raw bytes that nginx/apache log as "\\xAD" are normalised to "%ad" first, so the
unencoded variant of an exploit is caught too. One Hit is produced per CVE per
line, listing every pattern that matched.

The stateful worker-corruption detector (OOM on a worker, then that worker
reused) is the job of the continuous guard daemon and is referenced here, not
reimplemented.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from phpwarden.vulndb import Feed

_KIND_STREAM = {"request-signature": "access", "response-signature": "response"}

# Common/Combined access-log line: IP - - [time] "request" status size "ref" "ua"
# An optional leading "vhost:port " prefix (nginx/apache vhost_combined) is accepted.
_ACCESS_RE = re.compile(
    r'^(?:[\w.\-]+(?::\d+)?\s+)?(?P<ip>\d[\d.]*|[0-9a-fA-F:]+)\s+\S+\s+\S+\s+\[(?P<when>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})'
    r'(?:\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?)?')

_HEXESC = re.compile(r"\\x([0-9a-fA-F]{2})")      # how servers log raw bytes
_PCT = re.compile(r"%([0-9a-fA-F]{2})")
_PCT_BYTE = re.compile(r"^%[0-9a-f]{2}$")
_WORD = re.compile(r"^[a-z_][a-z0-9_]*$")


def parse_access_line(line: str) -> dict:
    """Best-effort structured fields from a common/combined access-log line."""
    m = _ACCESS_RE.match(line.strip())
    if not m:
        return {}
    out = {k: (m.group(k) or "") for k in ("ip", "when", "req", "status", "ua")}
    try:
        out["log_ts"] = int(datetime.strptime(out["when"], "%d/%b/%Y:%H:%M:%S %z").timestamp())
    except (ValueError, OverflowError):
        out["log_ts"] = None
    return out


def _normalize(s: str) -> str:
    return _HEXESC.sub(lambda m: "%" + m.group(1), s).lower()


def _decoded(s: str) -> bytes:
    return _PCT.sub(lambda m: chr(int(m.group(1), 16)), s).encode("latin-1", "replace")


def _valid_utf8(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _target(req: str):
    """("/path", "query") from 'GET /path?q=1 HTTP/1.1' (or the raw string)."""
    parts = req.split(" ")
    tgt = parts[1] if len(parts) >= 2 and parts[1].startswith("/") else req
    path, _, query = tgt.partition("?")
    return path, query


def _pattern_hits(pat: str, path: str, query: str, whole: str) -> bool:
    """Does one (lower-cased, normalised) pattern fire on this request?"""
    if _PCT_BYTE.match(pat):
        byte = int(pat[1:], 16)
        if pat in path and (byte < 0x20 or not _valid_utf8(_decoded(path))):
            return True
        if pat in query and not _valid_utf8(_decoded(query)):
            return True
        return False
    if _WORD.match(pat):
        return re.search(re.escape(pat) + r"\s*(=|%3d)", whole) is not None
    return pat in whole


@dataclass
class Hit:
    cve_id: str
    kind: str
    pattern: str
    line_no: int
    excerpt: str
    note: str
    ip: str = ""
    when: str = ""
    request: str = ""
    status: str = ""
    ua: str = ""
    log_ts: Optional[int] = None


class SignatureScanner:
    def __init__(self, feed: Feed):
        self.sigs = []        # (cve_id, kind, stream, pattern, note)
        seen = set()
        for cve in feed.cves:
            for det in cve.detectors:
                kind = det.get("kind")
                if kind not in _KIND_STREAM:
                    continue
                stream = det.get("on", _KIND_STREAM[kind])
                for pat in det.get("patterns", []):
                    key = (cve.id, kind, pat.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    self.sigs.append((cve.id, kind, stream, pat, det.get("note", "")))
        self.worker_corruption_cves = [
            c.id for c in feed.cves if "worker-corruption" in c.detector_kinds()]
        # set by scan_file
        self.scanned_lines = 0
        self.total_hits = 0
        self.truncated = False

    def scan_line(self, line: str, stream: str = "access", line_no: int = 0) -> List[Hit]:
        parsed = parse_access_line(line) if stream == "access" else {}
        if parsed.get("req"):
            path, query = _target(_normalize(parsed["req"]))
        else:
            # not a recognisable access line (raw request dump, other formats):
            # fall back to the whole line, treated as a path
            path, query = _normalize(line.strip()), ""
        whole = path + ("?" + query if query else "")
        per_cve = {}      # cve_id -> (kind, [patterns], note)
        for cve_id, kind, sig_stream, pat, note in self.sigs:
            if sig_stream != stream:
                continue
            if _pattern_hits(_normalize(pat), path, query, whole):
                entry = per_cve.setdefault(cve_id, (kind, [], note))
                entry[1].append(pat)
        hits = []
        for cve_id, (kind, pats, note) in per_cve.items():
            hits.append(Hit(cve_id, kind, ", ".join(pats), line_no, line.strip()[:300], note,
                            ip=parsed.get("ip", ""), when=parsed.get("when", ""),
                            request=parsed.get("req", ""), status=parsed.get("status", ""),
                            ua=parsed.get("ua", ""), log_ts=parsed.get("log_ts")))
        return hits

    def scan_file(self, path, stream: str = "access", max_hits: int = 500) -> List[Hit]:
        """Scan a whole log. Keeps at most `max_hits` Hit objects but scans EVERY
        line (so total_hits is accurate and nothing is silently skipped); sets
        self.truncated when more hits existed than were kept. Raises
        FileNotFoundError / IsADirectoryError / OSError for unusable input —
        callers must not report a missing file as "clean"."""
        p = Path(path)
        if p.is_dir():
            raise IsADirectoryError(f"{path} is a directory, not a log file")
        if not p.is_file():
            raise FileNotFoundError(f"log file not found: {path}")
        out = []
        self.scanned_lines = self.total_hits = 0
        with p.open(errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                self.scanned_lines = i
                hits = self.scan_line(line, stream, i)
                self.total_hits += len(hits)
                room = max_hits - len(out)
                if room > 0:
                    out.extend(hits[:room])
        self.truncated = self.total_hits > len(out)
        return out
