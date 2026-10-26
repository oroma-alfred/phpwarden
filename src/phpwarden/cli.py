"""phpwarden command-line interface.

  phpwarden scan                 assess this host against the whole CVE feed
  phpwarden scan --version 8.3.10 --sapi fpm --os linux
  phpwarden feed status          show the active feed and whether it is licensed
  phpwarden feed update          pull the latest feed (needs a license key)
  phpwarden detect ACCESS_LOG    scan a log for exploitation signatures

Exit codes (shared by every subcommand; usable as a CI gate):
  0   nothing applies / clean
  1   exposed (scan), vulnerable packages or components found (deps, wordpress),
      signature hits (detect), or the feed update failed
  2   possibly exposed (scan only)
  3   PHP version unknown (scan only)
  4   input error: missing/unreadable file, bad lockfile, cannot write --out
  5   results could not be uploaded to --report-to (only when the local
      result was otherwise 0; a non-zero local result always wins)
  64  usage error (unknown flag, missing argument) — EX_USAGE, never 2, so it
      cannot be confused with "possibly exposed"
"""
from __future__ import annotations

import argparse
import json
import sys

from phpwarden import __version__
from phpwarden import report as reportgen
from phpwarden import rules as rulegen
from phpwarden import wordpress as wp
from phpwarden.deps import rank_findings, scan_lock
from phpwarden.detect import SignatureScanner
from phpwarden.engine import Environment, assess, summarize
from phpwarden.env import detect as detect_env
from phpwarden.feed import FeedManager
from phpwarden import version as V

ICON = {"EXPOSED": "EXPOSED ", "POSSIBLY_EXPOSED": "POSSIBLE", "CLEARED": "cleared "}

EX_USAGE = 64          # sysexits.h: command-line usage error
EX_REPORT_FAILED = 5   # --report-to upload failed on an otherwise clean run

EXIT_CODES_HELP = """\
exit codes:
  0  clean          1  exposed / vulnerable / hits   2  possibly exposed (scan)
  3  version unknown (scan)                          4  input or --out error
  5  --report-to upload failed (clean run)          64 usage error
"""


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error, which collides with scan's
    "possibly exposed". Exit 64 (EX_USAGE) instead, message on stderr."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(EX_USAGE)


def _combine(rc: int, reported: bool) -> int:
    """Fold the --report-to outcome into a result code: a non-zero local result
    always wins; a clean run whose upload failed exits 5."""
    if rc:
        return rc
    return 0 if reported else EX_REPORT_FAILED


def _scan(args):
    fm = FeedManager()
    feed = fm.current()
    if args.version:
        ver = V.parse(args.version)
        if ver is None:
            # "8.5" or "garbage" used to be assessed silently as "unknown"
            sys.stderr.write(f"error: --version {args.version!r} is not a PHP version (expected X.Y.Z)\n")
            return 3
        env = Environment(version=ver, sapi=args.sapi, os=args.os)
    else:
        env = detect_env(php_binary=args.php)
        if args.sapi:
            env.sapi = args.sapi
        if args.os:
            env.os = args.os
    findings = assess(env, feed)
    s = summarize(findings)

    doc = {
        "php_version": str(env.version) if env.version else None,
        "sapi": env.sapi, "os": env.os,
        "feed_version": feed.feed_version, "feed_source": fm.source(),
        "summary": s,
        "findings": [{
            "cve": f.cve.id, "verdict": f.verdict, "confidence": f.confidence,
            "severity": f.cve.severity, "cvss": f.cve.cvss,
            "exploited_in_wild": f.cve.exploited_in_wild, "ransomware": f.cve.ransomware,
            "epss": f.cve.epss, "epss_percentile": f.cve.epss_percentile,
            "title": f.cve.title, "fixed": f.fixed, "reasons": f.reasons,
            "remediation": f.cve.remediation,
        } for f in findings if f.verdict != "CLEARED"],
    }
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        ver = str(env.version) if env.version else "unknown"
        print(f"phpwarden {__version__}  php={ver} sapi={env.sapi or '?'} os={env.os or '?'}  "
              f"feed={feed.feed_version} ({fm.source()})")
        print(f"  {s['exposed']} exposed, {s['possibly_exposed']} possible, {s['cleared']} cleared; "
              f"worst={s['worst_severity']}")
        if s["exploited_in_wild"]:
            print(f"  exploited in the wild: {', '.join(s['exploited_in_wild'])}")
        for f in findings:
            if f.verdict == "CLEARED":
                continue
            print(f"\n  [{ICON[f.verdict]}] {f.cve.id}  {f.cve.severity} (CVSS {f.cve.cvss})"
                  f"{_risk(f.cve.exploited_in_wild, f.cve.epss, f.cve.epss_percentile, f.cve.ransomware)}")
            print(f"      {f.cve.title}")
            for r in f.reasons:
                print(f"      - {r}")
            if f.fixed:
                print(f"      fixed in: {f.fixed}")
            print(f"      fix: {f.cve.remediation}")
        if s["exposed"] == 0 and s["possibly_exposed"] == 0:
            print("  No exposure found against the current feed.")

    # Local results are printed BEFORE the upload is attempted, so a dead SaaS
    # never hides them; the upload outcome only changes the exit code.
    reported = _maybe_report(args, doc)
    # Exit codes (documented): 0 nothing applies, 1 exposed, 2 possibly exposed,
    # 3 PHP version unknown. "Unknown" must win over 2: every CVE is only
    # "possible" BECAUSE the version is unknown, and 3 tells the operator why.
    if env.version is None:
        return _combine(3, reported)
    if s["exposed"]:
        return _combine(1, reported)
    if s["possibly_exposed"]:
        return _combine(2, reported)
    return _combine(0, reported)


def _feed(args):
    fm = FeedManager()
    if args.feed_cmd == "update":
        res = fm.update()
        print(json.dumps(res, indent=2) if args.json else _fmt_feed_update(res))
        return 0 if res["status"] in ("updated", "current", "no_license") else 1
    res = fm.status()
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"feed {res['feed_version']} ({res['channel']}): "
              f"{res['cve_count']} engine CVEs, {res['composer_count']} Composer, "
              f"{res['wp_count']} WordPress ({res['total_advisories']} total)")
        valid = res["license_valid"]
        valid_s = "unknown (run `feed update`)" if valid is None else ("valid" if valid else "REJECTED")
        print(f"  source={res['source']}, license_key_set={res['license_key_set']}, "
              f"license_valid={valid_s}")
        if not res["license_key_set"]:
            print("  Running the free community feed. Set PHPWARDEN_LICENSE for the maintained channel.")
        elif valid is False:
            print("  The feed server rejected this license key; the community feed stays in effect.")
    return 0


def _fmt_feed_update(res):
    st = res["status"]
    if st == "updated":
        added = ", ".join(res["added_cves"]) or "none"
        return (f"feed updated {res['from']} -> {res['to']} "
                f"({res['total_cves']} CVEs; new: {added})")
    if st == "no_license":
        return res["message"]
    http = f" [HTTP {res['http_status']}]" if res.get("http_status") else ""
    return f"{st}{http}: {res.get('message', res.get('feed_version',''))}"


def _detect(args):
    feed = FeedManager().current()
    scanner = SignatureScanner(feed)
    try:
        hits = scanner.scan_file(args.logfile)
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as e:
        # a missing or unreadable log must never be reported as "clean"
        sys.stderr.write(f"error: {e}\n")
        return 4
    doc = {"logfile": args.logfile,
           "scanned_lines": scanner.scanned_lines,
           "total_hits": scanner.total_hits,
           "truncated": scanner.truncated,
           "hits": [h.__dict__ for h in hits],
           "worker_corruption_cves": scanner.worker_corruption_cves}
    if scanner.truncated:
        sys.stderr.write(f"note: {scanner.total_hits} hits in {scanner.scanned_lines} lines; "
                         f"showing the first {len(hits)}\n")
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        if not hits:
            print(f"No exploitation signatures found in {args.logfile}.")
        else:
            print(f"{len(hits)} signature hit(s) in {args.logfile}:")
            for h in hits:
                print(f"  line {h.line_no}: {h.cve_id} ({h.kind}, pattern {h.pattern!r}) — {h.note}")
                print(f"      {h.excerpt}")
        if scanner.worker_corruption_cves:
            print(f"\nNote: {', '.join(scanner.worker_corruption_cves)} need the continuous "
                  f"guard daemon (worker-corruption detection), not log signatures.")
    return _combine(1 if hits else 0, _maybe_report(args, doc))


def _deps(args):
    from pathlib import Path as _P
    # A missing or malformed lockfile (or a composer.json handed in by mistake)
    # must be an error, not "No known-vulnerable Composer packages".
    lp = _P(args.lockfile)
    if not lp.is_file():
        sys.stderr.write(f"error: lockfile not found: {args.lockfile}\n")
        return 4
    try:
        lock_doc = json.loads(lp.read_text())
    except ValueError as e:
        sys.stderr.write(f"error: {args.lockfile} is not valid JSON: {e}\n")
        return 4
    if not isinstance(lock_doc, dict) or not any(k in lock_doc for k in ("packages", "packages-dev")):
        sys.stderr.write(f"error: {args.lockfile} is not a composer.lock (no \"packages\" section"
                         + (" — pass composer.lock, not composer.json)" if "require" in lock_doc else ")") + "\n")
        return 4
    feed = FeedManager().current()
    findings = scan_lock(args.lockfile, feed)
    # reachability: is each vulnerable package actually referenced in your code?
    reach = {}
    if not getattr(args, "no_reachability", False):
        project = getattr(args, "project", None) or str(_P(args.lockfile).resolve().parent)
        try:
            from phpwarden.deps import analyze_reachability
            reach = analyze_reachability(args.lockfile, project)
        except Exception:  # noqa: BLE001  (reachability is best-effort)
            reach = {}
    # KEV > reach (used > unknown > unreferenced > dev-only) > EPSS > CVSS; the
    # JSON list, the text output and the dashboard all share this order.
    findings = rank_findings(findings, reach)
    doc = {"lockfile": args.lockfile, "vulnerable": [{
        "package": f.package, "installed": f.installed, "cve": f.advisory.cve,
        "severity": f.advisory.severity, "cvss": f.advisory.cvss,
        "known_exploited": f.advisory.known_exploited, "ransomware": f.advisory.ransomware,
        "epss": f.advisory.epss, "epss_percentile": f.advisory.epss_percentile,
        "title": f.advisory.title, "fixed": f.fixed,
        "reach": reach.get(f.package, "unknown")} for f in findings]}
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        if not findings:
            print(f"No known-vulnerable Composer packages in {args.lockfile} (feed {feed.feed_version}).")
        else:
            kev = sum(1 for f in findings if f.advisory.known_exploited)
            print(f"{len(findings)} vulnerable package(s) in {args.lockfile}; "
                  f"{kev} actively exploited (KEV). Ranked by exploitation risk, then reachability:")
            for f in findings:
                print(f"\n  {f.package} {f.installed}  {f.advisory.cve} "
                      f"{_sev(f.advisory.severity, f.advisory.cvss)}"
                      f"{_risk(f.advisory.known_exploited, f.advisory.epss, f.advisory.epss_percentile, f.advisory.ransomware)}")
                print(f"      {f.advisory.title}")
                print(f"      fixed in: {', '.join(f.fixed)}")
                r = reach.get(f.package, "unknown")
                if r != "unknown":
                    print(f"      reachability: {r}")
    return _combine(1 if findings else 0, _maybe_report(args, doc))


def _sev(severity, cvss):
    """Format severity with CVSS only when it carries a real score."""
    if cvss and cvss > 0:
        return f"{severity} (CVSS {cvss:g})"
    return severity if severity != "unknown" else "severity n/a"


def _risk(known, epss, pct, ransomware=False):
    """Compact real-world-exploitation tag: KEV and/or EPSS probability."""
    parts = []
    if known:
        parts.append("KEV·ransomware" if ransomware else "KEV")
    if epss is not None:
        parts.append(f"EPSS {epss * 100:.0f}% (p{pct * 100:.0f})")
    return "  [" + ", ".join(parts) + "]" if parts else ""


def _maybe_report(args, doc) -> bool:
    """POST this result to a phpwarden SaaS, if --report-to is set.

    Returns True when no upload was requested or it succeeded, False when the
    upload failed (network error or non-2xx) — callers fold that into the exit
    code via `_combine`. Callers print their local results BEFORE calling this."""
    import os
    import urllib.request
    url = getattr(args, "report_to", None) or os.environ.get("PHPWARDEN_REPORT_URL")
    token = getattr(args, "report_token", None) or os.environ.get("PHPWARDEN_REPORT_TOKEN")
    if not url:
        return True
    body = json.dumps(doc).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {token}" if token else "",
                                          "User-Agent": "phpwarden/2"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
            res = json.loads(r.read())
        sys.stderr.write(f"reported to {url}: stored {res.get('stored', '?')} findings"
                         + (f", NEW actively-exploited: {', '.join(res['new_kev'])}"
                            if res.get("new_kev") else "") + "\n")
        return True
    except Exception as e:  # noqa: BLE001
        detail = f"HTTP {e.code}" if hasattr(e, "code") else e.__class__.__name__
        sys.stderr.write(f"report-to failed ({detail}); results shown locally, exit {EX_REPORT_FAILED} "
                         f"if the run was otherwise clean\n")
        return False


def _report_args(parser):
    parser.add_argument("--report-to", metavar="URL", help="POST results to a phpwarden SaaS ingest URL")
    parser.add_argument("--report-token", metavar="TOKEN", help="project ingest token (or PHPWARDEN_REPORT_TOKEN)")


def _write_out(path, text) -> bool:
    """Write generated output to --out; a missing directory or unwritable path
    is reported as `error: cannot write ...` instead of a traceback."""
    from pathlib import Path
    try:
        Path(path).write_text(text)
        return True
    except OSError as e:
        sys.stderr.write(f"error: cannot write {path}: {e.strerror or e}\n")
        return False


def _rules(args):
    feed = FeedManager().current()
    text = rulegen.generate(feed, args.format)
    if args.out:
        if not _write_out(args.out, text):
            return 4
        print(f"wrote {args.format} rules to {args.out}")
    else:
        print(text)
    return 0


def _wordpress(args):
    feed = FeedManager().current()
    findings = wp.scan(args.path, feed)
    doc = {"wordpress": args.path, "host": args.host, "findings": [{
        "kind": f.component.kind, "slug": f.component.slug, "version": f.component.version,
        "cve": f.advisory.cve, "severity": f.advisory.severity, "cvss": f.advisory.cvss,
        "known_exploited": f.advisory.known_exploited, "ransomware": f.advisory.ransomware,
        "epss": f.advisory.epss, "epss_percentile": f.advisory.epss_percentile,
        "title": f.advisory.title, "fixed": f.fixed} for f in findings]}
    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        inv = wp.inventory(args.path)
        print(f"WordPress at {args.path}: {len(inv)} components scanned, {len(findings)} vulnerable.")
        for f in findings:
            print(f"\n  {f.component.kind} {f.component.slug} {f.component.version}  "
                  f"{f.advisory.cve} {_sev(f.advisory.severity, f.advisory.cvss)}"
                  f"{_risk(f.advisory.known_exploited, f.advisory.epss, f.advisory.epss_percentile, f.advisory.ransomware)}")
            print(f"      {f.advisory.title}")
            print(f"      fixed in: {', '.join(f.fixed)}")
        if not inv:
            print("  (no WordPress install detected at that path)")
    return _combine(1 if findings else 0, _maybe_report(args, doc))


def _report(args):
    rows = reportgen.load_rows(args.files)
    feed = FeedManager().current()
    html_out = reportgen.render_html(rows, feed.feed_version)
    if args.out:
        if not _write_out(args.out, html_out):
            return 4
        print(f"wrote fleet report ({len(rows)} findings) to {args.out}")
    else:
        print(html_out)
    return 0


def main(argv=None):
    # _Parser exits 64 on usage errors (argparse's default 2 is "possibly
    # exposed"); add_subparsers() reuses the parent's class, so the subcommand
    # parsers inherit it.
    p = _Parser(prog="phpwarden",
                description="PHP exposure and exploitation guard.",
                epilog=EXIT_CODES_HELP,
                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"phpwarden {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="assess this host (or a given version) against the feed")
    sc.add_argument("--php", default="php", help="php binary (default: php)")
    sc.add_argument("--version", dest="version", help="assess an explicit version instead of the local one")
    sc.add_argument("--sapi", choices=["fpm", "cgi", "cli"], help="override detected SAPI")
    sc.add_argument("--os", choices=["linux", "windows", "darwin"], help="override detected OS")
    sc.add_argument("--json", action="store_true")
    _report_args(sc)
    sc.set_defaults(func=_scan)

    fd = sub.add_parser("feed", help="show or update the CVE feed")
    fd.add_argument("feed_cmd", choices=["status", "update"])
    fd.add_argument("--json", action="store_true")
    fd.set_defaults(func=_feed)

    dt = sub.add_parser("detect", help="scan a log file for exploitation signatures")
    dt.add_argument("logfile")
    dt.add_argument("--json", action="store_true")
    _report_args(dt)
    dt.set_defaults(func=_detect)

    dp = sub.add_parser("deps", help="scan a composer.lock for vulnerable dependencies")
    dp.add_argument("lockfile")
    dp.add_argument("--json", action="store_true")
    dp.add_argument("--project", metavar="DIR",
                    help="project source dir for reachability (default: the lockfile's dir)")
    dp.add_argument("--no-reachability", action="store_true",
                    help="skip checking whether vulnerable packages are referenced in code")
    _report_args(dp)
    dp.set_defaults(func=_deps)

    rl = sub.add_parser("rules", help="generate WAF blocking rules from the feed signatures")
    rl.add_argument("--format", choices=["modsecurity", "nginx"], default="modsecurity")
    rl.add_argument("--out", help="write to a file instead of stdout")
    rl.set_defaults(func=_rules)

    wpc = sub.add_parser("wordpress", help="scan a WordPress install for vulnerable core/plugins/themes")
    wpc.add_argument("path", help="path to the WordPress root")
    wpc.add_argument("--host", help="host label for fleet reports")
    wpc.add_argument("--json", action="store_true")
    _report_args(wpc)
    wpc.set_defaults(func=_wordpress)

    rp = sub.add_parser("report", help="aggregate JSON results into an HTML fleet dashboard")
    rp.add_argument("files", nargs="+", help="JSON files from scan/deps/wordpress --json")
    rp.add_argument("--out", help="write HTML to a file instead of stdout")
    rp.set_defaults(func=_report)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
