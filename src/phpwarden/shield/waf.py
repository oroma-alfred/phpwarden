"""Translate shield library rules into edge WAF rules (ModSecurity and nginx).

The shield rules describe the request shape an exploit needs (see library.py). The
same shape can be enforced at the edge, so the per-CVE "virtual patch" download has
a real rule for every CVE the library covers, not only the few with a feed signature.

ModSecurity can express every condition: decoded parameters, cookies, headers and the
request body are all addressable, and conditions are AND-ed with `chain`.

nginx cannot read the request body, POST parameters or decoded values. A rule is
emitted for nginx only when every condition is on the path, the raw query string,
a cookie or a header; otherwise the file says so and points to ModSecurity or the
shield, instead of shipping a rule that silently misses the exploit."""
from __future__ import annotations

import re

from phpwarden.shield.library import LIBRARY

MODSEC_ID_BASE = 9101000

# Exploited CVEs with no request-level rule, and why. The download says so instead of
# offering a rule that cannot work. Engine memory-corruption bugs keep the runtime guard.
NO_RULE = {
    "CVE-2026-109618": ("guard", "a memory-corruption bug in the PHP engine with no public request shape; "
                        "the runtime guard restarts a corrupted PHP-FPM worker until you upgrade"),
    "CVE-2026-109619": ("guard", "a memory-corruption bug in the PHP engine with no public request shape; "
                        "the runtime guard restarts a corrupted PHP-FPM worker until you upgrade"),
    "CVE-2020-11023": ("patch", "a jQuery bug that runs in the visitor's browser; nothing reaches the server"),
    "CVE-2020-28949": ("patch", "triggered by a member name inside a tar file the application extracts, not by the HTTP request"),
    "CVE-2020-36193": ("patch", "triggered by a member inside a tar file the application extracts, not by the HTTP request"),
    "CVE-2018-15133": ("patch", "the payload is encrypted with the application's APP_KEY and looks like a normal token; rotate the key and upgrade"),
    "CVE-2025-23209": ("patch", "needs the site's security key, so the request looks legitimate; rotate the key and upgrade"),
    "CVE-2026-9082": ("patch", "PostgreSQL SQL injection with no published request shape yet"),
    "CVE-2026-71362": ("patch", "an authorization flaw with no published request shape; upgrade, then invalidate customer sessions"),
    "CVE-2021-21311": ("patch", "Adminer SSRF: the only request signal (the elastic/clickhouse driver) also blocks legitimate use; upgrade or remove Adminer"),
    "CVE-2021-44026": ("patch", "which search parameter real exploits use is not confirmed, so a rule would guess"),
}
_EMAIL_XSS = ("patch", "the payload arrives inside an email and fires in the reader's browser; the HTTP request to Roundcube is normal")
for _c in ("CVE-2025-68461", "CVE-2024-42009", "CVE-2024-37383", "CVE-2020-13965", "CVE-2023-43770", "CVE-2023-5631", "CVE-2020-35730"):
    NO_RULE[_c] = _EMAIL_XSS
NGINX_OK = {"query", "cookie", "header"}


def rules_for_cve(cve_id):
    return [r for r in LIBRARY if r.get("cve") == cve_id]


def _q(rx):
    """Regex inside a double-quoted directive argument."""
    # \" in a regex is just a quote: normalise, then escape every quote exactly once
    return rx.replace('\\"', '"').replace('"', '\\"')


def raw_path_rx(rx):
    """The library path regex, applied to the raw request line (path + query). Anchor it
    to the path part so a query string can't satisfy it: '^' stays, a trailing '$' also
    accepts '?', anything else is searched within the path only."""
    end = rx.endswith("$") and not rx.endswith("\\$")
    core = rx[:-1] if end else rx
    tail = "(?:\\?|$)" if end else ""
    if core.startswith("^"):
        return core + tail
    return "^[^?]*(?:" + core + ")" + tail


# ---------------------------------------------------------------- ModSecurity

def _modsec_target(c):
    loc, name, rx = c.get("in"), c.get("name"), c.get("re")
    if loc == "query":
        return "QUERY_STRING", rx or "."
    if loc == "body":
        return "REQUEST_BODY", rx or "."
    if loc == "param":
        if name in (None, "*"):
            return ("ARGS", rx) if rx else ("&ARGS", None)
        # '|' separates variables in ModSecurity, so no alternation inside the selector:
        # the exact name, plus PHP array forms name[...]
        exact, arr = f"ARGS:{name}", f"ARGS:/^{re.escape(name)}\\[/"
        return (f"{exact}|{arr}", rx) if rx else (f"&{exact}|&{arr}", None)
    if loc == "param_name":
        return ("ARGS_NAMES", rx) if rx else ("&ARGS", None)
    if loc == "cookie":
        var = "REQUEST_COOKIES" if name in (None, "*") else f"REQUEST_COOKIES:{name}"
        return (var, rx) if rx else ("&" + var, None)
    if loc == "header":
        var = f"REQUEST_HEADERS:{name}"
        return (var, rx) if rx else ("&" + var, None)
    if loc == "file_name":                       # FILES = original upload filenames
        return ("FILES", rx) if rx else ("&FILES", None)
    if loc == "any":
        return "ARGS|REQUEST_COOKIES|REQUEST_BODY", rx
    if loc == "any_or_path":
        return "ARGS|REQUEST_COOKIES|REQUEST_BODY|REQUEST_FILENAME|QUERY_STRING", rx
    raise ValueError(f"unknown condition location {loc!r}")


def _modsec_op(rx):
    return '"@gt 0"' if rx is None else f'"@rx (?is){_q(rx)}"'


def modsec_lines(rule, rid, dry_run=False):
    action = "pass,log,auditlog" if dry_run else "deny,status:403,log"
    label = "phpwarden DRY-RUN (would block)" if dry_run else "phpwarden"
    # plain text only: '%' starts a macro, backslashes and quotes break the action list
    note = re.sub(r"[^A-Za-z0-9 .,:;()/_=<>@#+-]", "", (rule.get("description") or "").replace("\t", " "))
    first_actions = (f"id:{rid},phase:2,{action},t:none,"
                     f"msg:'{label}: {rule.get('cve') or rule['id']} ({rule['id']})',"
                     f"logdata:'{note[:180]}',tag:'phpwarden',tag:'{rule.get('cve') or 'generic'}'")
    checks = []
    if rule.get("path"):
        checks.append(None)                       # rendered below: decoded OR raw path
    for c in rule.get("all", []):
        checks.append(_modsec_target(c))
    if not checks:
        return []
    out = [f"# {rule.get('cve') or 'generic'} / {rule['id']}: {rule.get('description', '')}"]
    for i, chk in enumerate(checks):
        last = i == len(checks) - 1
        if chk is None:
            # one SecRule cannot apply two regexes; the raw-line regex is a superset
            # anchor of the path, so match it against both variables
            var, rx = "REQUEST_FILENAME|REQUEST_URI_RAW", raw_path_rx(rule["path"])
        else:
            var, rx = chk
        if i == 0:
            acts = first_actions + ("" if last else ",chain")
        else:
            acts = "t:none" + ("" if last else ",chain")
        out.append(f'{"SecRule" if i == 0 else "    SecRule"} {var} {_modsec_op(rx)} "{acts}"')
    return out


# ---------------------------------------------------------------- nginx

def nginx_expressible(rule):
    return bool(rule.get("path") or rule.get("all")) and all(c.get("in") in NGINX_OK for c in rule.get("all", []))


def _nginx_var(c):
    loc, name = c.get("in"), c.get("name")
    if loc == "query":
        return "$args"
    if loc == "cookie":
        return "$http_cookie" if name in (None, "*") else "$cookie_" + re.sub(r"[^A-Za-z0-9_]", "_", name)
    if loc == "header":
        return "$http_" + name.lower().replace("-", "_")
    raise ValueError(loc)


def nginx_lines(rule, n, dry_run=False):
    """One rule as nginx `if` blocks. nginx `if` has no AND/OR, so every condition sets
    its own flag variable (any of its alternatives may set it), the flags are joined,
    and the last `if` fires only when all of them are set."""
    if not nginx_expressible(rule):
        return []
    conds = []                                    # each: list of alternative tests
    if rule.get("path"):
        conds.append([f'$uri ~* "{_q(rule["path"])}"',
                      f'$request_uri ~* "{_q(raw_path_rx(rule["path"]))}"'])
    for c in rule.get("all", []):
        v, rx = _nginx_var(c), c.get("re")
        conds.append([f'{v} ~* "{_q(rx)}"' if rx else f'{v} ~ "."'])
    out = [f"# {rule.get('cve') or 'generic'} / {rule['id']}: {rule.get('description', '')}"]
    hit = (f'set $phpwarden_would_block "{rule.get("cve") or rule["id"]}";' if dry_run else "return 403;")
    if len(conds) == 1 and len(conds[0]) == 1:
        out.append(f"if ({conds[0][0]}) {{ {hit} }}")
        return out
    flags = []
    for i, alts in enumerate(conds):
        f = f"phpwarden_r{n}_{i}"; flags.append(f)
        out.append(f'set ${f} "";')
        for alt in alts:
            out.append(f'if ({alt}) {{ set ${f} "1"; }}')
    joined = "".join("${" + f + "}" for f in flags)
    out.append(f'set $phpwarden_r{n} "{joined}";')
    out.append(f'if ($phpwarden_r{n} = "{"1" * len(flags)}") {{ {hit} }}')
    return out


def waf_for_cve(cve_id, fmt, dry_run=False, id_base=MODSEC_ID_BASE):
    """(lines, covered, skipped): rendered rule lines for every library rule on this CVE,
    the rule ids rendered, and the ids nginx cannot express."""
    lines, covered, skipped = [], [], []
    for rule in rules_for_cve(cve_id):
        k = LIBRARY.index(rule)            # stable per rule: two downloads never clash
        if fmt == "nginx":
            ls = nginx_lines(rule, k, dry_run)
        else:
            ls = modsec_lines(rule, id_base + k, dry_run)
        if ls:
            lines += ls + [""]
            covered.append(rule["id"])
        else:
            skipped.append(rule["id"])
    return lines, covered, skipped
