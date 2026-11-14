"""phpwarden command-line interface.

  phpwarden scan                 assess this host against the whole CVE feed
  phpwarden deps composer.lock   Composer dependencies, with reachability
  phpwarden wordpress PATH       WordPress core, plugins and themes
  phpwarden integrity PATH       WordPress files against wordpress.org checksums
  phpwarden rules                WAF rules (ModSecurity / nginx) from the feed
  phpwarden report FILES         aggregate JSON results into a fleet page
  phpwarden scan --version 8.3.10 --sapi fpm --os linux
  phpwarden feed status          show the active feed and whether it is licensed
  phpwarden feed update          pull the latest feed (free weekly; maintained with a license key)
  phpwarden detect ACCESS_LOG    scan a log for exploitation signatures
  phpwarden probe URL            safe live HTTP check of a site you own
  phpwarden code PATH            scan your own PHP code for high-signal security bugs
  phpwarden assess PATH --url U --log L   one ranked verdict from every view

Exit codes (shared by every subcommand; usable as a CI gate):
  0   nothing applies / clean
  1   exposed (scan), vulnerable packages or components found (deps, wordpress),
      signature hits (detect), high/critical findings (code, probe), or the feed
      update failed
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
from phpwarden import sarif as sarifgen
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
  0  clean
  1  exposed (scan) / vulnerable (deps, wordpress) / signature hits (detect) /
     tampered files (integrity) / high or critical findings (code, probe; probe
     also on any known-exploited finding) / act-now or this-week items (assess) /
     feed update failed
  2  possibly exposed (scan)       3  PHP version unknown (scan)
  4  input error: missing file, no WordPress install, site unreachable, --out
  5  --report-to upload failed (clean run)          64 usage error
"""


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error, which collides with scan's
    "possibly exposed". Exit 64 (EX_USAGE) instead, message on stderr."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(EX_USAGE)


def _fmt(args) -> str:
    """Output format: --json is the older spelling of --format json."""
    return "json" if getattr(args, "json", False) else (getattr(args, "format", None) or "text")


def _format_arg(parser):
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                        help="output format (sarif: SARIF 2.1.0 for GitHub code scanning and other tools; --json = --format json)")


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
    elif _fmt(args) == "sarif":
        print(json.dumps(sarifgen.scan(doc), indent=2))
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
        if not res["license_key_set"]:
            print(f"  source={res['source']}, license: none (free channel)")
        else:
            valid_s = "unknown (run `feed update`)" if valid is None else ("valid" if valid else "REJECTED")
            print(f"  source={res['source']}, license_key_set=True, license_valid={valid_s}")
        if not res["license_key_set"]:
            print("  Running the free community feed. `phpwarden feed update` pulls the free weekly "
                  "snapshot; set PHPWARDEN_LICENSE for the maintained channel.")
        elif valid is False:
            print("  The feed server rejected this license key; the community feed stays in effect.")
    return 0


def _fmt_feed_update(res):
    st = res["status"]
    if st == "updated":
        added = ", ".join(res["added_cves"]) or "none"
        chan = " [free weekly]" if res.get("channel") == "free-weekly" else ""
        return (f"feed updated {res['from']} -> {res['to']}{chan} "
                f"({res['total_cves']} engine CVEs; new engine CVEs: {added})")
    if st == "current" and res.get("channel") == "free-weekly":
        return f"current: {res['message']}"
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
    elif _fmt(args) == "sarif":
        print(json.dumps(sarifgen.deps(doc, lp.read_text()), indent=2))
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
        tag = f"EPSS {epss * 100:.0f}%"
        if pct is not None:          # percentile is optional in the feed
            tag += f" (p{pct * 100:.0f})"
        parts.append(tag)
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
    parser.add_argument("--report-to", metavar="URL", help="POST results to the phpwarden dashboard (https://app.phpwarden.io/v1/reports)")
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
    if args.replay:
        try:
            rep = rulegen.replay(feed, args.replay)
        except OSError as e:
            sys.stderr.write(f"error: {e}\n")
            return 4
        if args.json:
            print(json.dumps(rep, indent=2))
            return 0
        print(f"Replayed {rep['scanned_lines']} log lines against the blocking rules "
              f"(feed {rep['feed_version']}): {rep['would_block']} request(s) would be blocked.")
        for c in rep["by_cve"]:
            flag = (f"  <- {c['served_2xx_3xx']} were answered 2xx/3xx, check these for false positives"
                    if c["served_2xx_3xx"] else "")
            print(f"  {c['cve']}: {c['requests']} request(s){flag}")
            print(f"      e.g. line {c['sample_line']}: {c['sample'][:160]}")
        if rep["top_paths"]:
            print("  top paths:   " + ", ".join(f"{p['path']} ({p['requests']})" for p in rep["top_paths"][:5]))
        if rep["top_clients"]:
            print("  top clients: " + ", ".join(f"{c['ip']} ({c['requests']})" for c in rep["top_clients"][:5]))
        if not rep["would_block"]:
            print("  Nothing in this log matches; enabling the rules would not have changed any response.")
        elif not rep["review"]:
            print("  None of the matching requests had been answered 2xx/3xx: no sign of false positives.")
        return 0
    text = rulegen.generate(feed, args.format, dry_run=args.dry_run)
    if args.out:
        if not _write_out(args.out, text):
            return 4
        print(f"wrote {args.format} rules to {args.out}" + (" (dry-run: log only)" if args.dry_run else ""))
    else:
        print(text)
    return 0


def _wordpress(args):
    # A wrong path must not read as "0 vulnerable": that would pass a CI gate on a typo.
    inv = wp.inventory(args.path)
    if not inv:
        sys.stderr.write(f"error: no WordPress install found at {args.path} "
                         f"(give the folder that contains wp-includes/ and wp-content/)\n")
        return 4
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
    elif _fmt(args) == "sarif":
        print(json.dumps(sarifgen.wordpress(doc), indent=2))
    else:
        print(f"WordPress at {args.path}: {len(inv)} components scanned, {len(findings)} vulnerable.")
        for f in findings:
            print(f"\n  {f.component.kind} {f.component.slug} {f.component.version}  "
                  f"{f.advisory.cve} {_sev(f.advisory.severity, f.advisory.cvss)}"
                  f"{_risk(f.advisory.known_exploited, f.advisory.epss, f.advisory.epss_percentile, f.advisory.ransomware)}")
            print(f"      {f.advisory.title}")
            print(f"      fixed in: {', '.join(f.fixed)}")
    return _combine(1 if findings else 0, _maybe_report(args, doc))


def _probe(args):
    from urllib.parse import urlsplit
    from phpwarden import probe as pr
    url = args.url if "://" in args.url else "https://" + args.url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        sys.stderr.write(f"error: {args.url!r} is not an http(s) URL\n")
        return 4
    token = args.token or pr.local_token(parts.hostname)
    if args.print_token:
        print(f"To let phpwarden run its active checks on {parts.hostname}, prove the site is yours.\n"
              f"Do ONE of these, then run: phpwarden probe {args.url}\n\n"
              f"  1. DNS TXT record on {parts.hostname}:\n       phpwarden-verify={token}\n"
              f"  2. A file at {parts.scheme}://{parts.netloc}/.well-known/phpwarden-verify.txt containing:\n       {token}\n"
              f"  3. A tag in the homepage <head>:\n       <meta name=\"phpwarden-verify\" content=\"{token}\">\n\n"
              f"Without it, probe only reads the homepage response (passive mode).")
        return 0
    res = pr.run_probe(url, token=token, active=False if args.passive else None,
                       max_requests=args.max_requests)
    if args.json:
        print(json.dumps(res, indent=2))
    elif _fmt(args) == "sarif":
        print(json.dumps(pr.to_sarif(res), indent=2))
    else:
        print(pr.to_text(res))
        if res["mode"] == "passive" and not args.passive:
            print(f"\n  Passive only: {parts.hostname} is not verified as yours. "
                  f"Run `phpwarden probe {args.url} --print-token` to enable the active checks.")
    if any("homepage unreachable" in n for n in res.get("notes", [])):
        sys.stderr.write(f"error: could not reach {url}\n")
        return 4
    return pr.exit_code(res)


def _code(args):
    from pathlib import Path as _P
    from phpwarden import code as codescan
    if args.list_rules:
        rules = codescan.list_rules()
        if args.json:
            print(json.dumps(rules, indent=2))
        else:
            for r in rules:
                opt = "" if r.get("default", True) else "  (opt-in: --all-rules)"
                print(f"  {r['id']:<34} {r['severity']:<8} {r['cwe']:<8} {r['title']}{opt}")
            print(f"\n{len(rules)} rules. Suppress one finding with a comment: // phpwarden-ignore: <rule-id>")
        return 0
    root = _P(args.path)
    if not root.exists():
        sys.stderr.write(f"error: path not found: {args.path}\n")
        return 4
    # A vulnerable dependency changes how bad some code findings are (a known
    # gadget chain makes unserialize() of user input worse), so pass those in.
    lock_findings = None
    lock = (root if root.is_dir() else root.parent) / "composer.lock"
    if lock.is_file():
        try:
            lock_findings = [{"package": f.package, "cve": f.advisory.cve,
                              "known_exploited": f.advisory.known_exploited}
                             for f in scan_lock(str(lock), FeedManager().current())]
        except Exception:  # noqa: BLE001 — context is best-effort
            lock_findings = None
    res = codescan.scan_project(str(root), include_tests=args.include_tests,
                                lock_findings=lock_findings, rules=args.rule or None,
                                all_rules=args.all_rules)
    order = ["low", "medium", "high", "critical"]
    if args.min_severity != "low":
        keep = set(order[order.index(args.min_severity):])
        res["findings"] = [f for f in res["findings"] if f["severity"] in keep]
        res["summary"] = {s: sum(1 for f in res["findings"] if f["severity"] == s) for s in reversed(order)}
    if args.json:
        print(json.dumps(res, indent=2))
    elif _fmt(args) == "sarif":
        print(json.dumps(codescan.to_sarif(res), indent=2))
    else:
        print(codescan.to_text(res))
    return codescan.exit_code(res)


def _assess(args):
    from pathlib import Path as _P
    from phpwarden import verdict as vd
    if not args.path and not args.url and not args.probe_json:
        sys.stderr.write("error: give a project path, --url, or --probe-json\n")
        return EX_USAGE
    if args.path and not _P(args.path).is_dir():
        sys.stderr.write(f"error: not a directory: {args.path}\n")
        return 4
    probe_result = None
    try:
        if args.probe_json:
            probe_result = vd.load(args.probe_json)
        baseline = vd.load(args.baseline) if args.baseline else None
    except (OSError, ValueError) as e:
        sys.stderr.write(f"error: {e}\n")
        return 4
    if args.url and probe_result is None:
        from urllib.parse import urlsplit
        from phpwarden import probe as pr
        url = args.url if "://" in args.url else "https://" + args.url
        host = urlsplit(url).hostname
        if not host:
            sys.stderr.write(f"error: {args.url!r} is not a URL\n")
            return 4
        probe_result = pr.run_probe(url, token=args.token or pr.local_token(host))
        if any("homepage unreachable" in n for n in probe_result.get("notes", [])):
            sys.stderr.write(f"error: could not reach {url}\n")
            return 4
    try:
        res = vd.assess(args.path, probe_result=probe_result, logfile=args.log, run_code=not args.no_code)
    except OSError as e:                      # unreadable access log
        sys.stderr.write(f"error: {e}\n")
        return 4
    diff = vd.compare(baseline, res) if baseline else None
    if args.out and not _write_out(args.out, json.dumps(res, indent=2)):
        return 4
    if args.json:
        print(json.dumps({**res, "changes": diff} if diff is not None else res, indent=2))
    else:
        print(vd.to_text(res, diff))
        if args.out:
            print(f"\nsaved to {args.out}; after fixing, rerun with --baseline {args.out} to get verified fixes")
    return vd.exit_code(res)


def _integrity(args):
    from phpwarden import integrity as integ
    res = integ.check(args.path, locale=args.locale, plugins=not args.no_plugins)
    doc = integ.to_doc(res)
    if not res.core_version:
        # same rule as every other command: a missing input is exit 4, never "clean"
        sys.stderr.write(f"error: no WordPress install found at {args.path}\n")
        return 4
    if args.json:
        print(json.dumps(doc, indent=2))
        return 1 if res.tampered else 0
    labels = {"php-in-uploads": "PHP file in uploads", "unexpected": "does not belong",
              "modified": "modified", "missing": "missing"}
    bad = [i for i in res.issues if i.kind != "missing"]
    print(f"WordPress {res.core_version} at {args.path}: {res.files_checked} files compared with wordpress.org, "
          f"{len(bad)} problem{'s' if len(bad) != 1 else ''}.")
    for i in res.issues:
        flag = "  SUSPICIOUS" if i.suspicious else ""
        print(f"\n  {labels.get(i.kind, i.kind):20} {i.path}  ({i.component}){flag}")
        for pid in i.suspicious:
            print(f"      matches: {integ.describe(pid)}")
    if res.verified:
        print(f"\n  verified against official checksums: {len(res.verified)} component(s)")
    if res.unverified:
        print(f"  could not be verified: {len(res.unverified)} component(s)")
        for u in res.unverified[:40]:
            print(f"      {u['component']}: {u['reason']}")
    if not res.issues:
        print("\n  No modified or unexpected files in the components that could be verified.")
    print("\n  This compares files with wordpress.org checksums and looks for common backdoor code.\n"
          "  It is not a signature-based malware scanner.")
    return 1 if res.tampered else 0


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
                description="PHP vulnerability scanner: engine, Composer, WordPress, your own code and the live site, "
                            "ranked by real-world exploitation (CISA KEV, then EPSS, then CVSS).",
                epilog=EXIT_CODES_HELP,
                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"phpwarden {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="assess this host (or a given version) against the feed")
    sc.add_argument("--php", default="php", help="php binary (default: php)")
    sc.add_argument("--version", dest="version", help="assess an explicit version instead of the local one")
    sc.add_argument("--sapi", choices=["fpm", "cgi", "cli"], help="override detected SAPI")
    sc.add_argument("--os", choices=["linux", "windows", "darwin"], help="override detected OS")
    sc.add_argument("--json", action="store_true", help="machine-readable JSON output")
    _format_arg(sc)
    _report_args(sc)
    sc.set_defaults(func=_scan)

    fd = sub.add_parser("feed", help="show or update the CVE feed")
    fd.add_argument("feed_cmd", choices=["status", "update"],
                    help="status: show the active feed; update: pull the free weekly snapshot, or the "
                         "maintained channel when PHPWARDEN_LICENSE is set")
    fd.add_argument("--json", action="store_true", help="machine-readable JSON output")
    fd.set_defaults(func=_feed)

    dt = sub.add_parser("detect", help="scan a log file for exploitation signatures")
    dt.add_argument("logfile")
    dt.add_argument("--json", action="store_true", help="machine-readable JSON output")
    _report_args(dt)
    dt.set_defaults(func=_detect)

    dp = sub.add_parser("deps", help="scan a composer.lock for vulnerable dependencies")
    dp.add_argument("lockfile")
    dp.add_argument("--json", action="store_true", help="machine-readable JSON output")
    _format_arg(dp)
    dp.add_argument("--project", metavar="DIR",
                    help="project source dir for reachability (default: the lockfile's dir)")
    dp.add_argument("--no-reachability", action="store_true",
                    help="skip checking whether vulnerable packages are referenced in code")
    _report_args(dp)
    dp.set_defaults(func=_deps)

    rl = sub.add_parser("rules", help="generate WAF blocking rules from the feed signatures")
    rl.add_argument("--format", choices=["modsecurity", "nginx"], default="modsecurity",
                    help="rule syntax (default: modsecurity)")
    rl.add_argument("--out", help="write to a file instead of stdout")
    rl.add_argument("--dry-run", action="store_true",
                    help="generate rules that only log what they would block")
    rl.add_argument("--replay", metavar="ACCESS_LOG",
                    help="report what the rules would have blocked in an existing access log")
    rl.add_argument("--json", action="store_true", help="with --replay: JSON output")
    rl.set_defaults(func=_rules)

    wpc = sub.add_parser("wordpress", help="scan a WordPress install for vulnerable core/plugins/themes")
    wpc.add_argument("path", help="path to the WordPress root")
    wpc.add_argument("--host", help="host label for fleet reports")
    wpc.add_argument("--json", action="store_true", help="machine-readable JSON output")
    _format_arg(wpc)
    _report_args(wpc)
    wpc.set_defaults(func=_wordpress)

    asx = sub.add_parser("assess", help="one ranked verdict from every view: installed versions, your code, "
                                        "the live site from outside, and attacks in the access log")
    asx.add_argument("path", nargs="?", help="project or site root (composer.lock, WordPress, PHP code)")
    asx.add_argument("--url", help="also check the live site from outside (see `probe`)")
    asx.add_argument("--token", help="ownership token for --url (default: this machine's token)")
    asx.add_argument("--probe-json", metavar="FILE", help="use a saved `probe --json` result instead of --url")
    asx.add_argument("--log", metavar="ACCESS_LOG", help="also check what is being attacked in this access log")
    asx.add_argument("--no-code", action="store_true", help="skip the scan of your own PHP code")
    asx.add_argument("--out", metavar="FILE", help="save this assessment (JSON) to compare against later")
    asx.add_argument("--baseline", metavar="FILE",
                     help="an earlier --out file: report what is fixed and verified, still open, and new")
    asx.add_argument("--json", action="store_true", help="machine-readable JSON output")
    asx.set_defaults(func=_assess)

    cd = sub.add_parser("code", help="scan your own PHP code for high-signal security bugs "
                                     "(injection, unsafe deserialization, exposed WordPress/Laravel handlers)")
    cd.add_argument("path", nargs="?", default=".", help="project directory or a single PHP file (default: .)")
    cd.add_argument("--rule", action="append", metavar="ID", help="only run this rule (repeatable)")
    cd.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low",
                    help="only report findings at or above this severity (default: low)")
    cd.add_argument("--include-tests", action="store_true", help="also scan tests/ and *Test.php")
    cd.add_argument("--all-rules", action="store_true",
                    help="also run the opt-in rules (noisier; see --list-rules)")
    cd.add_argument("--list-rules", action="store_true", help="list the rules and exit")
    cd.add_argument("--json", action="store_true", help="machine-readable JSON output")
    _format_arg(cd)
    cd.set_defaults(func=_code)

    pb = sub.add_parser("probe", help="safe live HTTP check of a site: exposed files, debug endpoints, "
                                      "versions matched against the feed (GET/HEAD only; active checks need "
                                      "proof the site is yours)")
    pb.add_argument("url", help="site URL, e.g. https://example.com")
    pb.add_argument("--token", help="ownership token (default: this machine's token for the host)")
    pb.add_argument("--print-token", action="store_true",
                    help="show how to verify ownership of the site, then exit")
    pb.add_argument("--passive", action="store_true", help="read the homepage response only")
    pb.add_argument("--max-requests", type=int, default=60, help="request budget (default 60)")
    pb.add_argument("--json", action="store_true", help="machine-readable JSON output")
    _format_arg(pb)
    pb.set_defaults(func=_probe)

    ig = sub.add_parser("integrity", help="check WordPress core and plugin files against wordpress.org "
                                          "checksums; flag injected files and backdoor code")
    ig.add_argument("path", help="path to the WordPress root")
    ig.add_argument("--locale", default="en_US", help="WordPress locale of the install (default en_US)")
    ig.add_argument("--no-plugins", action="store_true", help="check core and uploads only")
    ig.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ig.set_defaults(func=_integrity)

    rp = sub.add_parser("report", help="aggregate JSON results into an HTML fleet dashboard")
    rp.add_argument("files", nargs="+", help="JSON files from scan/deps/wordpress --json")
    rp.add_argument("--out", help="write HTML to a file instead of stdout")
    rp.set_defaults(func=_report)

    args = p.parse_args(argv)
    if getattr(args, "format", None) == "json":   # --format json is --json
        args.json = True
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
