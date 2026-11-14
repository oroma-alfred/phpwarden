"""Layer 5: authorisation, IDOR and CSRF checks on framework entry points.

These rules look at entry points as a whole (a route and the code it reaches),
not at a single source-to-sink flow, so they run after the taint engine and use
its summaries (which functions write state) and the call graph.

- laravel-route-no-auth: a state-changing route (POST/PUT/PATCH/DELETE,
  resource) whose controller method reaches a database write, with no auth
  middleware on the route or its group and no authorize()/Gate check in the
  controller.
- symfony-route-no-auth: a #[Route] controller action that persists or removes
  entities with no #[IsGranted] / denyAccessUnlessGranted().
- laravel-idor-hint: an authenticated route that loads a model from a route
  parameter (route model binding or find($id)) and changes it, with no policy,
  Gate or ownership check in the method.
- laravel-csrf-excluded: a URI excluded from CSRF verification that matches a
  state-changing web route.

All are reported at medium: public write endpoints (contact forms, webhooks
with their own signature checks) and authorisation configured outside the code
(security.yaml access_control, a gateway) are legitimate and can't be seen here.
"""
from __future__ import annotations

import fnmatch

from .taint import Finding, _has_authz, _lname

STATE_VERBS = frozenset({"post", "put", "patch", "delete", "any", "match", "resource", "apiresource",
                         "resources", "apiresources"})
ROUTE_VERBS = STATE_VERBS | {"get", "options", "view", "redirect"}
_AUTH_MW_PREFIXES = ("auth", "can:", "role:", "permission:", "verified", "admin", "signed")


def _short(name):
    return _lname(name).rsplit("\\", 1)[-1]


def _strings(v):
    """Literal strings in a string or array node."""
    if v is None:
        return []
    if v.kind == "String":
        return [v.value or ""]
    if v.kind == "Array":
        out = []
        for it in v.items:
            if it is not None and it.value is not None and it.value.kind == "String":
                out.append(it.value.value or "")
        return out
    return []


def _authy(strings):
    return any(s.startswith(_AUTH_MW_PREFIXES) for s in strings)


def laravel_routes(project):
    """{(file rel, line of the verb call): {"verb", "uri", "auth"}} for routes/*.php."""
    out = {}
    for fi in project.files.values():
        if fi.vendor or not fi.rel.replace("\\", "/").startswith("routes/"):
            continue
        _walk_routes(fi.stmts or [], False, fi, out)
    return out


def _chain(e):
    calls = []
    x = e
    while x is not None and x.kind in ("MethodCall", "NullsafeMethodCall"):
        calls.append(x)
        x = x.obj
    if x is not None and x.kind == "StaticCall" and x.cls.kind == "Name" and _short(x.cls.name) == "route":
        calls.append(x)
        return calls
    return None


def _walk_routes(nodes, authed, fi, out):
    stack = [(n, authed) for n in nodes]
    while stack:
        n, auth = stack.pop()
        if n is None:
            continue
        if isinstance(n, list):
            stack.extend((x, auth) for x in n)
            continue
        if n.kind in ("MethodCall", "StaticCall", "NullsafeMethodCall"):
            ch = _chain(n)
            if ch is not None:
                a = auth
                for c in ch:
                    nm = c.name.lower() if isinstance(c.name, str) else ""
                    if nm in ("middleware", "withmiddleware") and c.args:
                        if _authy(_strings(c.args[0].value)):
                            a = True
                    if nm == "group" and c.args and c.args[0].value is not None and c.args[0].value.kind == "Array":
                        for it in c.args[0].value.items:
                            if it is not None and it.key is not None and it.key.kind == "String" and \
                                    it.key.value == "middleware" and _authy(_strings(it.value)):
                                a = True
                for c in ch:
                    nm = c.name.lower() if isinstance(c.name, str) else ""
                    if nm in ROUTE_VERBS:
                        uri = c.args[0].value.value if c.args and c.args[0].value is not None and \
                            c.args[0].value.kind == "String" else None
                        if nm == "match" and len(c.args) > 1:
                            verbs = [v.lower() for v in _strings(c.args[0].value)]
                            uri = c.args[1].value.value if c.args[1].value is not None and \
                                c.args[1].value.kind == "String" else None
                            nm = "match" if set(verbs) - {"get", "head", "options"} else "get"
                        out[(fi.rel, c.line)] = {"verb": nm, "uri": uri, "auth": a}
                    if nm == "group":
                        for arg in c.args:
                            v = arg.value
                            if v is not None and v.kind in ("Closure", "ArrowFn"):
                                body = v.body if v.kind == "Closure" else [v.expr]
                                stack.extend((x, a) for x in body)
                continue
        if n.kind in ("Function", "Class"):
            continue
        stack.extend((x, auth) for x in n.children())


def _ownership_check(rec):
    """auth()->id(), Auth::id()/user(), $request->user() used in the method: an
    ownership comparison or a query scoped to the user is likely."""
    stack = list(rec.body or [])
    while stack:
        x = stack.pop()
        if x is None:
            continue
        k = x.kind
        if k == "Call" and x.func.kind == "Name" and _short(x.func.name) in ("auth", "abort_if", "abort_unless"):
            return True
        if k == "StaticCall" and x.cls.kind == "Name" and _short(x.cls.name) == "auth":
            return True
        if k in ("MethodCall", "NullsafeMethodCall") and isinstance(x.name, str) and \
                x.name.lower() in ("user", "owns", "isowner", "belongsto"):
            return True
        if k in ("Function", "Class", "Closure", "ArrowFn"):
            continue
        stack.extend(x.children())
    return False


def _model_param_or_find(rec):
    """A route parameter typed with a class (route model binding) or a
    find()/findOrFail()/firstOrFail() lookup in the method."""
    for prm in rec.params or []:
        if prm.type is not None and any(n[:1].isupper() and n.lower() not in ("request", "string", "int")
                                        for n in prm.type.names) and not any(
                n.lower().endswith("request") for n in prm.type.names):
            return True
    stack = list(rec.body or [])
    while stack:
        x = stack.pop()
        if x is None:
            continue
        if x.kind in ("StaticCall", "MethodCall") and isinstance(x.name, str) and \
                x.name.lower() in ("find", "findorfail", "firstorfail", "findorsave"):
            return True
        if x.kind in ("Function", "Class", "Closure", "ArrowFn"):
            continue
        stack.extend(x.children())
    return False


def check(eng, enabled=None):
    """Run the layer-5 entry-point rules; returns Finding objects."""
    p = eng.p
    cg = p.callgraph
    out = []

    def on(rule):
        return enabled is None or rule in enabled

    def add(rule, rec, msg, line=None, file=None):
        f = file or rec.file.rel
        ln = line or (rec.node.line if rec.node is not None else 1)
        out.append(Finding(rule, f, ln, 1, [{"file": f, "line": ln, "column": 1, "note": msg}], msg))

    def writes_from(key):
        ws = []
        for k in eng._reach([key], depth=3):
            s = eng.summaries.get(k)
            if s is not None:
                ws.extend(s.ormw)
        return ws

    routes = laravel_routes(p) if cg is not None else {}
    seen = set()
    if cg is not None and (on("laravel-route-no-auth") or on("laravel-idor-hint")):
        for e in cg.edges():
            if e.kind != "route" or e.callee not in eng.units or e.callee in seen:
                continue
            rec = eng.units[e.callee]
            info = routes.get((e.file.rel if e.file is not None else "", e.line))
            if info is None:
                info = next((v for (f, ln), v in routes.items() if ln == e.line), None)
            if info is None or info["verb"] not in STATE_VERBS:
                continue
            seen.add(e.callee)
            if eng.unit_authz(e.callee):
                continue
            ws = writes_from(e.callee)
            if not ws:
                continue
            label = "%s::%s()" % (rec.cls.rsplit("\\", 1)[-1] if rec.cls else "?", rec.name)
            if not info["auth"] and on("laravel-route-no-auth"):
                add("laravel-route-no-auth", rec,
                    "%s route %s -> %s writes (%s at %s:%d) with no auth middleware and no authorize()/Gate check."
                    % (info["verb"].upper(), info["uri"] or "?", label, ws[0][0], ws[0][1], ws[0][2]))
            elif info["auth"] and on("laravel-idor-hint") and _model_param_or_find(rec) \
                    and not _ownership_check(rec):
                add("laravel-idor-hint", rec,
                    "%s changes a record loaded from a route parameter (%s at %s:%d) without a policy, Gate or "
                    "ownership check: any signed-in user may be able to change another user's record."
                    % (label, ws[0][0], ws[0][1], ws[0][2]))
    if on("symfony-route-no-auth"):
        from .models import symfony as SF
        for key, rec in eng.units.items():
            if rec.kind != "method" or rec.node is None or not SF.route_attribute(rec.node):
                continue
            if eng.unit_authz(key):
                continue
            ws = [w for w in writes_from(key) if w[0].lstrip("-> ").startswith(("persist", "remove", "flush"))
                  or "persist" in w[0] or "remove" in w[0]]
            if ws:
                add("symfony-route-no-auth", rec,
                    "Controller action %s::%s() persists or removes entities (%s at %s:%d) with no #[IsGranted] or "
                    "denyAccessUnlessGranted(); unless security.yaml access_control covers its path, anyone can "
                    "call it." % (rec.cls.rsplit("\\", 1)[-1] if rec.cls else "?", rec.name, ws[0][0], ws[0][1], ws[0][2]))
    if on("laravel-csrf-excluded") and routes:
        state_uris = [(f, ln, v["uri"]) for (f, ln), v in routes.items()
                      if v["verb"] in STATE_VERBS and v["uri"] and f.startswith("routes/web")]
        for fi in p.files.values():
            if fi.vendor:
                continue
            for node, patterns in _csrf_excepts(fi):
                for pat in patterns:
                    hits = [u for u in state_uris if fnmatch.fnmatch(u[2].strip("/"), pat.strip("/"))]
                    if hits:
                        msg = ("'%s' is excluded from CSRF verification and matches the state-changing route %s "
                               "(%s:%d). Fine for a third-party webhook that checks its own signature; otherwise "
                               "any site can submit this form as the signed-in user." % (pat, hits[0][2], hits[0][0],
                                                                                          hits[0][1]))
                        out.append(Finding("laravel-csrf-excluded", fi.rel, node.line, 1,
                                           [{"file": fi.rel, "line": node.line, "column": 1, "note": msg}], msg))
    return out


def _csrf_excepts(fi):
    """[(node, [patterns])]: `protected $except = [...]` in a class extending
    VerifyCsrfToken / ValidateCsrfToken, and ->validateCsrfTokens(except: [...])."""
    res = []
    stack = list(fi.stmts or [])
    while stack:
        x = stack.pop()
        if x is None:
            continue
        if x.kind == "Class" and x.get("parent"):
            sym = getattr(x, "sym", None)
            pn = _short(str(sym.parent if sym is not None and sym.parent else x.parent))
            if pn in ("verifycsrftoken", "validatecsrftoken"):
                for m in x.get("members") or []:
                    if getattr(m, "kind", "") == "Property":
                        for pr in m.get("props") or [m]:
                            nm = getattr(pr, "name", "")
                            if str(nm).lstrip("$") == "except":
                                val = pr.get("default") if hasattr(pr, "get") else None
                                pats = _strings(val)
                                if pats:
                                    res.append((pr, pats))
        if x.kind in ("MethodCall", "NullsafeMethodCall") and isinstance(x.name, str) and \
                x.name.lower() == "validatecsrftokens":
            for a in x.args:
                if a is not None and (a.name == "except" or a.name is None):
                    pats = _strings(a.value)
                    if pats:
                        res.append((x, pats))
        stack.extend(x.children())
    return res
