"""Python mirror of the PHP agent's matching, for tests, benchmarks and replay.

The PHP agent (integrations/php-shield/phpwarden-shield.php) is what protects a
site; this module applies the same rules to a request described as a dict
({"method", "uri", "headers", "cookies", "body", "ctype"}) so the policy can be
tested and benchmarked without a web server. Keep the two in step: the test
suite runs the same requests through both and compares the verdicts.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote_plus, urlsplit

MAX_VALUES = 300
MAX_VALUE_LEN = 8192
MAX_BODY = 65536
_cache = {}


def _rx(pattern):
    r = _cache.get(pattern)
    if r is None:
        r = _cache[pattern] = re.compile(pattern, re.I | re.S)
    return r


def _php_key(k):
    """PHP turns '.' and ' ' in top-level keys into '_' and splits a[b][c]."""
    m = re.match(r"^([^\[]*)(.*)$", k)
    base = m.group(1).replace(".", "_").replace(" ", "_")
    return base + m.group(2)


def parse_request(req):
    uri = req.get("uri") or "/"
    sp = urlsplit(uri if "://" not in uri else uri)
    path, query = sp.path or "/", sp.query
    params = []                                     # (name, decoded value)
    for k, v in parse_qsl(query, keep_blank_values=True):
        params.append((_php_key(k), v))
    body = (req.get("body") or "")[:MAX_BODY]
    ctype = (req.get("ctype") or "").lower()
    if body and ctype.startswith("application/x-www-form-urlencoded"):
        for k, v in parse_qsl(body, keep_blank_values=True):
            params.append((_php_key(k), v))
    params = [(k, v[:MAX_VALUE_LEN]) for k, v in params[:MAX_VALUES]]
    headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
    cookies = {k: v for k, v in (req.get("cookies") or {}).items()}
    return {"method": (req.get("method") or "GET").upper(), "path": path, "query": query,
            "params": params, "headers": headers, "cookies": cookies,
            "body": body if not ctype.startswith("multipart/") else ""}


def _param_names(params):
    """Every key as PHP would expose it: 'mail[#post_render][]' gives
    'mail' and the nested keys '#post_render'."""
    out = []
    for k, _ in params:
        out.append(k)
        out.extend(re.findall(r"\[([^\]]*)\]", k))
    return out


def _cond(c, r):
    loc, name, pat = c.get("in"), c.get("name"), c.get("re")
    rx = _rx(pat) if pat else None
    if loc in ("path", "query", "body"):
        v = r[loc]
        return bool(v) and (rx is None or bool(rx.search(v)))
    if loc == "param":
        if name in (None, "*"):
            vals = [v for _, v in r["params"]]
        else:
            vals = [v for k, v in r["params"] if k == name or k.startswith(name + "[")]
            if not vals:
                return False
        return True if rx is None and vals else any(rx.search(v) for v in vals) if rx else False
    if loc == "param_name":
        return any(rx.search(n) for n in _param_names(r["params"])) if rx else bool(r["params"])
    if loc == "cookie":
        if name in (None, "*"):
            vals = list(r["cookies"].values())
        else:
            if name not in r["cookies"]:
                return False
            vals = [r["cookies"][name]]
        return True if rx is None else any(rx.search(v) for v in vals)
    if loc == "header":
        v = r["headers"].get((name or "").lower())
        if v is None:
            return False
        return True if rx is None else bool(rx.search(v))
    if loc in ("any", "any_or_path"):
        vals = [v for _, v in r["params"]] + list(r["cookies"].values()) + [r["body"]]
        if loc == "any_or_path":
            vals += [r["path"], r["query"], unquote_plus(r["path"])]
        return any(rx.search(v) for v in vals if v)
    return False


def match_rule(rule, req_or_parsed):
    r = req_or_parsed if "params" in req_or_parsed else parse_request(req_or_parsed)
    if rule.get("method") and r["method"] not in [m.upper() for m in rule["method"]]:
        return False
    if rule.get("path") and not _rx(rule["path"]).search(r["path"]):
        return False
    return all(_cond(c, r) for c in rule.get("all", []))


def evaluate(policy, req):
    """[(rule id, action)] for a request; action is 'block' only for promoted rules
    when the policy is in enforce mode."""
    r = parse_request(req)
    enforce = policy.get("mode") == "enforce"
    out = []
    for rule in policy.get("rules", []):
        if match_rule(rule, r):
            out.append((rule["id"], "block" if enforce and rule.get("mode") == "block" else "log"))
    return out
