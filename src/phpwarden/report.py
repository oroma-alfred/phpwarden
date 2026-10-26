"""Fleet dashboard — aggregate per-host JSON results into one HTML report.

Reads the JSON emitted by `scan`, `deps` and `wordpress` (any mix), normalises
every finding into one row, and renders a self-contained HTML page: summary
tiles plus a severity-sorted table. This is the CNAPP bridge — a fleet-wide
view of PHP exposure over time — not a cloud platform.
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


@dataclass
class Row:
    host: str
    source: str
    ident: str
    severity: str
    cvss: float
    status: str
    title: str
    fixed: str
    wild: bool
    epss: float = None
    reach: str = ""


def _rows_from_doc(host: str, doc: dict) -> List[Row]:
    """One Row per finding. Every numeric field goes through `_num` / `_fnum`
    and `fixed` through `_fixed`, for ALL three document types: a `cvss: null`,
    a string epss or a null fixed list in any one finding must never raise."""
    rows = []
    # scan output
    if "findings" in doc and "summary" in doc:
        for f in doc["findings"]:
            rows.append(Row(host, "engine", str(f["cve"]), _sev(f.get("severity")),
                            _num(f.get("cvss")), str(f.get("verdict") or ""),
                            str(f.get("title") or ""), _fixed(f.get("fixed")),
                            bool(f.get("exploited_in_wild")), _fnum(f.get("epss"))))
    # deps output
    if "vulnerable" in doc:
        for f in doc["vulnerable"]:
            rows.append(Row(host, "composer", f"{f['package']} {f.get('installed', '')} / {f['cve']}",
                            _sev(f.get("severity")), _num(f.get("cvss")), "EXPOSED",
                            str(f.get("title") or ""), _fixed(f.get("fixed")),
                            bool(f.get("known_exploited")), _fnum(f.get("epss")),
                            str(f.get("reach") or "")))
    # wordpress output
    if "wordpress" in doc and "findings" in doc:
        for f in doc["findings"]:
            if "slug" in f:
                rows.append(Row(host, f"wp-{f.get('kind') or '?'}",
                                f"{f['slug']} {f.get('version') or ''} / {f['cve']}",
                                _sev(f.get("severity")), _num(f.get("cvss")), "EXPOSED",
                                str(f.get("title") or ""), _fixed(f.get("fixed")),
                                bool(f.get("known_exploited")), _fnum(f.get("epss"))))
    return rows


_HOST_SUFFIX = re.compile(r"[-_.](deps|scan|wp|wordpress|detect)$", re.I)


def _num(v, default=0.0) -> float:
    """cvss as a float; None / "" / junk -> default (one bad field must not
    take the whole file out of the report)."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _fnum(v):
    """epss as float or None."""
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


def _sev(v) -> str:
    """severity as a lowercase label; None / "" -> "unknown"."""
    return str(v).lower() if v else "unknown"


def _fixed(v) -> str:
    """fixed-in versions as one display string: a list (deps/wp), a bare string
    (scan), or None / junk -> "-"."""
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v if x) or "-"
    return str(v) if v else "-"


def _host_of(doc, fp: Path) -> str:
    """Host label: the doc's own `host`, else the file stem with a tool suffix
    stripped so web1.json + web1-deps.json are ONE host, not two."""
    h = doc.get("host") if isinstance(doc, dict) else None
    return h or _HOST_SUFFIX.sub("", fp.stem)


def load_rows(paths, warn=None) -> List[Row]:
    """Rows from scan/deps/wordpress JSON files. Unreadable or wrong-shape inputs
    are reported through `warn(msg)` (default: stderr) and skipped — never
    silently, and never by crashing the whole report."""
    import sys
    warn = warn or (lambda m: sys.stderr.write(f"report: {m}\n"))
    rows = []
    for p in paths:
        fp = Path(p)
        try:
            doc = json.loads(fp.read_text())
        except OSError as e:
            warn(f"skipping {p}: {e.strerror or e}")
            continue
        except ValueError:
            warn(f"skipping {p}: not valid JSON")
            continue
        if not isinstance(doc, dict):
            warn(f"skipping {p}: not a phpwarden result document")
            continue
        try:
            rows.extend(_rows_from_doc(_host_of(doc, fp), doc))
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            warn(f"skipping {p}: unexpected document shape ({e.__class__.__name__}: {e})")
            continue
    rows.sort(key=lambda r: (0 if r.wild else 1, -(r.epss or 0),
                             _SEV_ORDER.get(r.severity, 9), -r.cvss))
    return rows


def render_html(rows: List[Row], feed_version: str = "") -> str:
    hosts = sorted({r.host for r in rows})
    crit = sum(1 for r in rows if r.severity == "critical")
    high = sum(1 for r in rows if r.severity == "high")
    wild = sum(1 for r in rows if r.wild)
    sev_color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
                 "low": "#65a30d", "unknown": "#6b7280"}

    def esc(s):
        return html.escape(str(s))

    def risk_cell(r):
        bits = []
        if r.wild:
            bits.append('<span class="kev">KEV</span>')
        if r.epss is not None:
            bits.append(f'{r.epss * 100:.0f}%')
        return " ".join(bits) or "-"

    trs = "\n".join(
        f'<tr><td>{esc(r.host)}</td><td><span class="src">{esc(r.source)}</span></td>'
        f'<td class="id">{esc(r.ident)}</td>'
        f'<td><span class="sev" style="background:{sev_color.get(r.severity,"#6b7280")}">'
        f'{esc(r.severity)}</span></td><td>{r.cvss:g}</td>'
        f'<td class="risk">{risk_cell(r)}</td>'
        f'<td>{esc(r.status)}</td>'
        f'<td>{esc(r.title)}</td><td class="fix">{esc(r.fixed)}</td></tr>'
        for r in rows)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>phpwarden fleet report</title>
<style>
:root {{ --bg:#ffffff; --fg:#111827; --muted:#6b7280; --card:#f3f4f6; --border:#e5e7eb; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme=light]) {{
  --bg:#0b0f17; --fg:#e5e7eb; --muted:#9ca3af; --card:#111827; --border:#1f2937; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; padding:24px 16px; }}
.wrap {{ max-width:1040px; margin:0 auto; }}
h1 {{ font-size:22px; margin:0 0 4px; }}
.sub {{ color:var(--muted); margin:0 0 20px; font-size:13px; }}
.tiles {{ display:flex; flex-wrap:wrap; gap:12px; margin-bottom:20px; }}
.tile {{ background:var(--card); border:1px solid var(--border); border-radius:10px;
  padding:14px 18px; min-width:120px; }}
.tile b {{ display:block; font-size:26px; line-height:1.1; }}
.tile span {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:.04em; }}
.id {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }}
.fix {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:var(--muted); }}
.src {{ background:var(--border); border-radius:5px; padding:1px 7px; font-size:11px; }}
.sev {{ color:#fff; border-radius:5px; padding:1px 8px; font-size:11px; font-weight:600; }}
.risk {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; white-space:nowrap; }}
.kev {{ background:#dc2626; color:#fff; border-radius:5px; padding:1px 6px; font-size:10px; font-weight:700; }}
.empty {{ color:var(--muted); padding:30px 0; text-align:center; }}
</style></head><body><div class="wrap">
<h1>phpwarden fleet report</h1>
<p class="sub">{len(rows)} findings across {len(hosts)} host(s){' · feed ' + esc(feed_version) if feed_version else ''}</p>
<div class="tiles">
  <div class="tile"><b>{len(rows)}</b><span>findings</span></div>
  <div class="tile"><b style="color:{sev_color['critical']}">{crit}</b><span>critical</span></div>
  <div class="tile"><b style="color:{sev_color['high']}">{high}</b><span>high</span></div>
  <div class="tile"><b style="color:{sev_color['critical']}">{wild}</b><span>actively exploited (KEV)</span></div>
  <div class="tile"><b>{len(hosts)}</b><span>hosts</span></div>
</div>
{"<table><thead><tr><th>Host</th><th>Source</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>Risk</th><th>Status</th><th>Detail</th><th>Fixed in</th></tr></thead><tbody>" + trs + "</tbody></table>" if rows else '<div class="empty">No findings. Every host assessed is clear against the current feed.</div>'}
</div></body></html>"""
