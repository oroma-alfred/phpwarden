"""AST engine entry point: parse, model, type, taint; findings in the
phpwarden-code result shape (each with a `trace`)."""
from __future__ import annotations

import os
import re

from phpwarden.code_rules import RULES_BY_ID, TAINT_SINKS

from .models import laravel as LV
from .models import php_builtins as B
from .project import Project
from .taint import TaintEngine
from .types import refine_callgraph

# Rules the AST engine decides. For files it parses cleanly, token-engine
# findings with these ids are replaced by the AST engine's.
TAINT_RULES = frozenset({s["rule"] for s in TAINT_SINKS} | {s["rule"] for s in B.SINKS} | {
    B.ECHO_RULE, B.INCLUDE_RULE, B.EVAL_RULE, B.BACKTICK_RULE, B.VARFUNC_RULE, B.HEADER_REDIRECT_RULE,
    "mass-assignment", "blade-raw", "twig-raw", "xss-response", "ssrf-http-client", "cmd-process",
    "mail-header-injection", "wp-option-key-tainted", "sql-doctrine",
    "wp-nopriv-ajax-no-auth", "wp-ajax-no-nonce", "wp-rest-open-write",
    "second-order-injection", "wp-admin-post-no-nonce", "laravel-route-no-auth", "symfony-route-no-auth",
    "laravel-idor-hint", "laravel-csrf-excluded",
} | {r for _a, _b, _c, _d, r in LV.STATIC_SINKS} | {r for _a, _b, _c, r in LV.METHOD_SINKS}) & set(RULES_BY_ID)

_TEST_FILE = re.compile(r"Test\.php$")
_VIA = re.compile(r"^call (?:[\w\\]*::)?(\w+)\(\) \((.+):(\d+)\)$")
_LOWER = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}


def _is_test(rel):
    parts = rel.lower().split("/")
    return any(p in ("test", "tests") for p in parts[:-1]) or bool(_TEST_FILE.search(rel))


def analyse(root, include_tests=False, enabled=None):
    """-> (findings as dicts, set of rel paths the AST engine handled, project)."""
    root = os.path.abspath(root)
    p = Project.load(root, skip_tests=not include_tests)
    refine_callgraph(p)

    def skip(fi):
        return fi.vendor or (not include_tests and _is_test(fi.rel))

    eng = TaintEngine(p, enabled=enabled, skip=skip)
    raw = eng.run()
    # second-order: request data stored under a fixed option / meta key, read
    # back elsewhere and used in a sink. A second pass treats those reads as
    # sources and reports only the flows that start from them.
    if eng.stored and (enabled is None or "second-order-injection" in enabled
                       or any(k[0] == "session" for k in eng.stored)):
        eng2 = TaintEngine(p, enabled=enabled, skip=skip)
        eng2.stored_sources = dict(eng.stored)
        raw2 = eng2.run()
        for f in raw2:
            if f.unit is not None:
                f.unit = f.unit if f.unit in eng.units else None
        # option/meta flows are reported as second-order-injection; session flows
        # keep the sink's rule (e.g. SQL injection) with a "stored in session" note
        raw = list(raw) + [f for f in raw2 if f.rule == "second-order-injection" or "stored in session at" in (f.message or "")]
    from . import authz
    raw = list(raw) + authz.check(eng, enabled)
    gadgets = _gadget_packages(root)
    handled = {fi.rel for fi in p.files.values()
               if not skip(fi) and not fi.errors and not fi.internal_error}
    lines_cache = {}
    out = []
    for f in raw:
        r = RULES_BY_ID.get(f.rule)
        if r is None:
            continue
        lines = lines_cache.get(f.file)
        if lines is None:
            try:
                with open(os.path.join(root, f.file), encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                lines = []
            lines_cache[f.file] = lines
        if _suppressed(lines, f.rule, f.line):
            continue
        snippet = lines[f.line - 1].strip()[:200] if 0 < f.line <= len(lines) else ""
        msg = r["description"]
        if f.rule.startswith("wp-") and f.message:
            msg = f.message
        else:
            for h in f.trace or []:
                m = _VIA.match(h.get("note", ""))
                if m:
                    msg = "%s (via %s() in %s:%s)" % (msg.rstrip("."), m.group(1).lower(), m.group(2), m.group(3))
                    break
        sev, ctx = r["severity"], []
        _m = re.search(r"stored in session at (\S+:\d+)", f.message or "")
        if _m:
            ctx = ["stored in session at " + _m.group(1)]
        if f.rule == "unserialize-tainted" and gadgets:
            sev, ctx = "critical", ["gadget-chain: " + gadgets[0]]
        # Request data that only reaches the sink after a capability /
        # authorisation check needs a logged-in privileged user: still reported,
        # one level lower, and marked so a reviewer can tell.
        if f.unit and eng.unit_authz(f.unit) and not f.rule.startswith(("wp-", "laravel-", "symfony-")):
            sev = _LOWER.get(sev, sev)
            ctx = ctx + ["requires-authenticated-admin"]
        out.append({"rule": f.rule, "title": r["title"], "severity": sev, "cwe": r["cwe"],
                    "file": f.file, "line": f.line, "column": f.col, "snippet": snippet,
                    "message": msg, "fix": r["fix"], "context": ctx, "trace": f.trace, "engine": "ast"})
    return out, handled, p


def _gadget_packages(root):
    """Installed packages with a known PHP deserialization gadget chain (PHPGGC families)."""
    import json
    from phpwarden.code_rules import GADGET_PACKAGES
    try:
        with open(os.path.join(root, "composer.lock"), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return []
    names = [p.get("name", "") for p in (doc.get("packages") or []) if isinstance(p, dict)]
    return [n for n in names if any(n == g or (g.endswith("/") and n.startswith(g)) for g in GADGET_PACKAGES)]


def _suppressed(lines, rid, line):
    for ln in (line, line - 1):
        if 1 <= ln <= len(lines) and "phpwarden-ignore" in lines[ln - 1]:
            m = re.search(r"phpwarden-ignore(?::\s*([\w,\s-]+))?", lines[ln - 1])
            ids = (m.group(1) or "").replace(",", " ").split()
            if not ids or rid in ids or "all" in ids:
                return True
    return False
