"""Laravel model: request sources, query/command/path/redirect/SSRF sinks,
mass assignment, Blade templates, route entry points, facades and factories."""
from __future__ import annotations

import os
import re

REQUEST_CLASSES = ("illuminate\\http\\request", "illuminate\\foundation\\http\\formrequest",
                   "symfony\\component\\httpfoundation\\request")
REQUEST_METHODS = {
    # name: (whole-bag?, args_needed)
    "input": "maybe", "query": "maybe", "post": "maybe", "get": "no", "all": "yes", "cookie": "no",
    "header": "no", "route": "no", "string": "no", "str": "no", "json": "maybe", "only": "no",
    "except": "yes", "collect": "maybe", "keys": "no", "server": "no", "file": "no", "segment": "no",
    "path": "no", "url": "no", "fullurl": "no", "getcontent": "no", "toarray": "yes", "safe": "no",
    "input_source": "no", "date": "no", "enum": "no",
}
# Typed accessors that return safe values.
REQUEST_SAFE_METHODS = {"integer", "boolean", "float", "has", "filled", "missing", "exists", "hasfile",
                        "ip", "method", "ismethod", "ajax", "wantsjson", "expectsjson", "bearertoken",
                        "user", "validate", "validatewithbag"}
FACADES = {
    "db": "illuminate\\support\\facades\\db", "request": "illuminate\\http\\request",
    "input": "illuminate\\http\\request", "http": "illuminate\\support\\facades\\http",
    "redirect": "illuminate\\support\\facades\\redirect", "storage": "illuminate\\support\\facades\\storage",
    "file": "illuminate\\support\\facades\\file", "process": "illuminate\\support\\facades\\process",
    "route": "illuminate\\support\\facades\\route", "response": "illuminate\\support\\facades\\response",
    "view": "illuminate\\support\\facades\\view", "mail": "illuminate\\support\\facades\\mail",
    "cache": "illuminate\\support\\facades\\cache", "app": "illuminate\\support\\facades\\app",
}
# app('request') / resolve('request') service ids -> class
SERVICE_IDS = {"request": "Illuminate\\Http\\Request", "db": "Illuminate\\Database\\DatabaseManager",
               "files": "Illuminate\\Filesystem\\Filesystem", "redirect": "Illuminate\\Routing\\Redirector"}
MODEL_BASE = "illuminate\\database\\eloquent\\model"

# Sinks keyed on facade/static calls and method names (receiver checks in taint.py)
STATIC_SINKS = [
    # (facade short name, method names, arg indices, kind, rule)
    ("db", ("raw",), (0,), "sql", "sql-laravel-raw"),
    ("db", ("select", "selectone", "statement", "unprepared", "insert", "update", "delete",
            "affectingstatement", "cursor", "scalar"), (0,), "sql", "sql-laravel-db"),
    ("http", ("get", "post", "put", "patch", "delete", "head", "send"), (0,), "url", "ssrf-laravel-http"),
    ("redirect", ("to", "away", "guest", "intended"), (0,), "redirect", "redirect-laravel"),
    ("storage", ("get", "readstream", "download", "response", "url", "path"), (0,), "path", "path-read"),
    ("storage", ("put", "putfile", "putfileas", "append", "prepend", "writestream", "copy", "move"), (0,), "path", "path-write"),
    ("storage", ("delete", "deletedirectory"), (0,), "path", "path-delete"),
    ("file", ("get", "sharedget", "lines", "requireonce", "getrequire"), (0,), "path", "path-read"),
    ("file", ("put", "append", "prepend", "replace", "copy", "move"), (0,), "path", "path-write"),
    ("file", ("delete", "deletedirectory", "cleandirectory"), (0,), "path", "path-delete"),
    ("process", ("run", "start", "command"), (0,), "cmd", "cmd-process"),
    ("response", ("download", "file"), (0,), "path", "path-readfile"),
    ("response", ("make",), (0,), "xss", "xss-response"),
]
# Method-name sinks on query builders / Eloquent (any receiver; names are distinctive)
METHOD_SINKS = [
    (("whereraw", "orwhereraw", "selectraw", "orderbyraw", "havingraw", "orhavingraw", "groupbyraw", "fromraw",
      "joinraw"), (0,), "sql", "sql-laravel-raw"),
]
# helper functions
FUNC_SINKS = [
    ("redirect", (0,), "redirect", "redirect-laravel"),
    ("response", (0,), "xss", "xss-response"),
]
# methods on a redirect() / Redirect / response() chain
CHAIN_SINKS = {
    "redirect": [(("to", "away", "guest", "intended"), (0,), "redirect", "redirect-laravel")],
    "response": [(("download", "file"), (0,), "path", "path-readfile"),
                 (("make",), (0,), "xss", "xss-response")],
    "http": [(("get", "post", "put", "patch", "delete", "head", "send"), (0,), "url", "ssrf-laravel-http")],
}
MASS_METHODS_STATIC = ("create", "forcecreate", "firstorcreate", "updateorcreate", "firstornew", "make", "insert")
MASS_METHODS = ("fill", "forcefill", "update", "create", "forcecreate", "updateorcreate", "firstorcreate")
FORCE_METHODS = ("forcefill", "forcecreate")

# FormRequest rules that leave no room for an injection payload.
SAFE_RULE_TOKENS = re.compile(r"^(integer|int|numeric|boolean|bool|digits(_between)?(:.*)?|email(:.*)?|uuid|ulid|"
                              r"date(_format:.*)?|in:.*|alpha|alpha_num|alpha_dash|ip|ipv4|ipv6|mac_address|"
                              r"exists:.*|decimal:.*|min:.*|max:.*|size:.*|between:.*|required|nullable|"
                              r"sometimes|present|filled|accepted|declined|bail|gt:.*|lt:.*|gte:.*|lte:.*)$", re.I)
RESTRICTIVE = re.compile(r"^(integer|int|numeric|boolean|bool|digits.*|email.*|uuid|ulid|date.*|in:.*|alpha|"
                         r"alpha_num|alpha_dash|ip.*|mac_address|exists:.*|decimal:.*|accepted|declined|regex:/\^.*\$/.*)$",
                         re.I)


def view_template_paths(root, name):
    """resources/views/<a/b>.blade.php for view('a.b')."""
    rel = name.replace(".", "/")
    out = []
    for base in ("resources/views", "views", "app/views"):
        for ext in (".blade.php", ".php"):
            p = os.path.join(root, base, rel + ext)
            if os.path.isfile(p):
                out.append(p)
    return out


_BLADE_RAW = re.compile(r"\{!!\s*(.*?)\s*!!\}", re.S)
_VAR = re.compile(r"\$([A-Za-z_]\w*)")
_DIRECT = re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\b|\brequest\(\s*['\"]|\brequest\(\)\s*->\s*(input|get|query|all)\b|"
                     r"\bRequest::(input|get|query|all)\b|\binput\(\s*['\"]")


def blade_raw_echoes(path):
    """[(line, expr, [var names], direct_request_access)] for {!! ... !!} in a Blade file."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return []
    out = []
    for m in _BLADE_RAW.finditer(src):
        expr = m.group(1)
        line = src.count("\n", 0, m.start()) + 1
        out.append((line, expr, _VAR.findall(expr), bool(_DIRECT.search(expr))))
    return out
