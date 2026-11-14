"""Whole-program taint engine on the AST (SAST stage B).

* Interprocedural and summary-based. Each unit (function, method, closure,
  file) gets a summary: which parameters reach which sinks, which parameters
  and sources reach the return value, and which parameters are written to
  `$this` properties. Summaries are computed callee-first over the strongly
  connected components of the call graph and iterated to a fixed point; a
  worklist re-analyses a unit when something it used changed (a callee's
  summary, a property store, a global, an included file's variables).
* Flow-sensitive inside a unit (statement order, branch joins, guards that end
  the request), field-sensitive for `$this->prop` and literal array keys.
* Types (types.py) resolve method calls; framework models (models/) supply
  sources, sinks, sanitizers and entry points.
* Every finding carries a trace: source, each hop, sink.

Taint values are dicts {origin: frozenset(kinds)}. An origin is an int (a real
source, see Origin) or ('p', i) for "parameter i of the unit being analysed".
"""
from __future__ import annotations

import os
import re

from phpwarden.code_rules import RULES_BY_ID

from .models import laravel as LV
from .models import php_builtins as B
from .models import symfony as SF
from .models import wordpress as WP
from .types import Types, join as tjoin

ALLK = B.ALL
SRC_KINDS = ALLK
SERVER_SRC_KINDS = ALLK - {"xss", "redirect", "url"}
MAX_ORIGINS = 4
MAX_HOPS = 10
MAX_RET_DEPTH = 3           # functions request data may be returned through
MAX_CALL_DEPTH = 2          # calls between the analysed unit and a sink
# Dynamic calls and HTTP clients are what frameworks do with their own
# configuration; file paths and includes are what plugin/theme loaders do with
# names they validated elsewhere. Those flows must be short to count.
_RULE_DEPTH = {"variable-function-tainted": 0, "call-user-func-tainted": 0, "ssrf-http-client": 1,
               "include-tainted": 1, "unserialize-tainted": 1, "path-read": 1, "path-readfile": 1,
               "path-write": 1, "path-delete": 1, "path-copy-rename": 1, "path-move-upload": 1,
               # query helpers are layered: page -> repository -> db wrapper -> driver
               "sql-db-query": 3, "sql-mysqli-query": 3, "sql-wpdb": 3, "sql-pg-query": 3, "sql-mysql-query": 3}
EMPTY = {}
_SKIP_KINDS = ("Function", "Class")
_PARAM_SAFE_TYPES = frozenset({"int", "integer", "float", "double", "bool", "boolean", "true", "false"})


class Origin:
    __slots__ = ("id", "desc", "file", "line", "col", "hops", "parent")

    def __init__(self, oid, desc, file, line, col, hops=(), parent=None):
        self.id = oid
        self.desc = desc
        self.file = file
        self.line = line
        self.col = col
        self.hops = hops
        self.parent = parent


class Summary:
    __slots__ = ("ret", "sinks", "propw", "writes", "guards", "nonce", "sig", "ormw")

    def __init__(self):
        self.ret = {}          # origin key -> kinds
        self.sinks = {}        # (pidx, rule, kind, file, line) -> steps tuple
        self.propw = {}        # prop -> {origin key: kinds}
        self.writes = []       # [(what, file, line)] state-changing WordPress calls
        self.guards = False    # nonce / capability check seen
        self.nonce = False
        self.sig = None
        self.ormw = []         # [(what, file, line)] Eloquent / Doctrine / DB writes

    def signature(self):
        return (tuple(sorted((str(k), tuple(sorted(v))) for k, v in self.ret.items())),
                tuple(sorted(self.sinks, key=repr)),
                tuple(sorted((p, tuple(sorted((str(k), tuple(sorted(v))) for k, v in d.items())))
                             for p, d in self.propw.items())),
                bool(self.writes), self.guards, self.nonce, bool(self.ormw))


# ------------------------------------------------------------- taint algebra
def t_union(a, b):
    if not a:
        return b
    if not b:
        return a
    out = dict(a)
    for k, v in b.items():
        cur = out.get(k)
        if cur is None:
            if len(out) >= MAX_ORIGINS and isinstance(k, int):
                continue
            out[k] = v
        elif cur != v:
            out[k] = cur | v
    return out


def t_remove(t, kinds):
    if not t:
        return t
    out = {}
    for k, v in t.items():
        nv = v - kinds
        if nv:
            out[k] = nv
    return out


def t_keep(t, kinds):
    if not t:
        return t
    out = {}
    for k, v in t.items():
        nv = v & kinds
        if nv:
            out[k] = nv
    return out


def t_has(t, kind):
    return any(kind in v for v in t.values())


def t_project(t, key):
    """Taint of t[key] when only the whole of t is known: request origins stay as
    they are, a whole-parameter marker ("p", i) becomes the key marker
    ("p", i, key), so callee summaries can record which array key reached a sink."""
    if not t:
        return t
    out = {}
    for o, v in t.items():
        if not isinstance(o, int) and len(o) == 2 and o[0] == "p":
            o = ("p", o[1], key)
        out[o] = out[o] | v if o in out else v
    return out


def _pidx(o):
    """Summary index of a parameter marker: i for the whole parameter, (i, key) for one array key."""
    return o[1] if len(o) == 2 else (o[1], o[2])


def env_join(a, b):
    if a is b:
        return a
    out = dict(a)
    for k, v in b.items():
        out[k] = t_union(out.get(k, EMPTY), v)
    return out


def _lname(n):
    return n.lstrip("\\").lower() if isinstance(n, str) else ""


def _short(n):
    return _lname(n).rsplit("\\", 1)[-1]


class Finding:
    __slots__ = ("rule", "file", "line", "col", "trace", "message", "unit")

    def __init__(self, rule, file, line, col, trace, message, unit=None):
        self.rule = rule
        self.file = file
        self.line = line
        self.col = col
        self.trace = trace
        self.message = message
        self.unit = unit        # function where the request data entered


# Authorisation checks that mean "only an authenticated, privileged user gets here".
_AUTHZ_FUNCS = frozenset({"current_user_can", "user_can", "is_super_admin", "current_user_can_for_blog",
                          "current_user_can_for_site", "author_can"})
_AUTHZ_METHODS = frozenset({"authorize", "authorizeforuser", "denyaccessunlessgranted", "isgranted",
                            "authorizeresource"})
_AUTHZ_STATIC = frozenset({("gate", "allows"), ("gate", "authorize"), ("gate", "check"), ("gate", "denies"),
                           ("gate", "any"), ("gate", "inspect")})
_AUTHZ_ATTRS = frozenset({"isgranted", "security", "can", "authorize"})
_AUTHZ_MIDDLEWARE = re.compile(r"^(auth(:|$)|can:|role:|permission:|verified$|admin$)")


# ===================================================================== engine
class TaintEngine:
    MAX_ANALYSES_FACTOR = 4

    def __init__(self, project, enabled=None, skip=None):
        self.p = project
        self.enabled = enabled
        self.skip = skip or (lambda fi: False)
        self.origins = []
        self.origin_unit = {}
        self.cur_unit = None
        self._authz = {}
        self._derived = {}
        self.summaries = {}
        self.file_env = {}           # file unit key -> {var: taint}  (real origins only)
        self.props = {}              # (class fq lower, prop) -> taint
        self.globals = {}            # var name -> taint
        self.findings = {}           # (rule, file, line) -> Finding
        self.templates = {}          # ("blade"|"twig", name) -> {var: taint}, plus where it was rendered
        self.template_sites = {}
        self.deps_props = {}
        self.deps_globals = {}
        self.deps_files = {}
        self.route_units = set()
        self.rest_open = []          # (callback keys, file, line)
        self.ajax_hooks = []         # ("nopriv"|"priv"|"adminpost", callback keys, file, line, action)
        self.stored = {}             # (store, key) -> (file, line): request data written to an option/meta
        self.stored_sources = None   # second pass: reads of those keys are sources (second-order)
        self.units = {}
        self.analyses = 0
        self.closure_env = {}        # closure key -> {captured var: taint} (real origins, from the parent)
        self.fn_globals = {}         # var -> taint assigned through `global $x` inside functions
        self.deps_closures = {}

    # -------------------------------------------------------------- origins
    def new_origin(self, desc, fi, node):
        o = Origin(len(self.origins), desc, fi.rel, node.line, node.col)
        self.origins.append(o)
        self.origin_unit[o.id] = self.cur_unit
        return o.id

    def root_unit(self, oid):
        o = self.origins
        while o[oid].parent is not None:
            oid = o[oid].parent
        return self.origin_unit.get(oid)

    def unit_authz(self, key):
        """Does this entry function require a privileged, authenticated user?
        Capability checks (WordPress), authorize()/Gate (Laravel), IsGranted /
        denyAccessUnlessGranted (Symfony), auth middleware on the controller."""
        if key in self._authz:
            return self._authz[key]
        rec = self.units.get(key)
        ok = False
        if rec is not None:
            nodes = [rec.node] if rec.node is not None else []
            nodes += list(rec.body or [])
            if rec.cls:
                c = self.p.get_class(rec.cls) if hasattr(self.p, "get_class") else None
                cnode = getattr(c, "node", None) if c is not None else None
                if cnode is not None:
                    for grp in cnode.get("attrs") or []:
                        nodes.append(grp)
                    for m in cnode.get("members") or []:
                        if getattr(m, "kind", "") == "Method" and str(getattr(m, "name", "")).lower() == "__construct":
                            nodes.append(m)
            ok = any(_has_authz(n) for n in nodes)
        self._authz[key] = ok
        return ok

    def derive(self, oid, hop):
        key = (oid, hop)
        hit = self._derived.get(key)
        if hit is not None:
            return hit
        base = self.origins[oid]
        hops = base.hops + (hop,) if len(base.hops) < MAX_HOPS else base.hops
        o = Origin(len(self.origins), base.desc, base.file, base.line, base.col, hops, parent=oid)
        self.origins.append(o)
        self._derived[key] = o.id
        return o.id

    # ------------------------------------------------------------- findings
    def report(self, rule, oid, fi, node, steps, note):
        root = oid
        while self.origins[root].parent is not None:
            root = self.origins[root].parent
        if self.origins[root].desc.startswith("stored session "):
            if self.stored_sources is None:
                return
            m = re.search(r"written from request data at (\S+):(\d+)", self.origins[root].desc)
            note = "%s (stored in session at %s:%s)" % (note, m.group(1), m.group(2)) if m else note
        elif self.origins[root].desc.startswith("stored "):
            if self.stored_sources is None:
                return
            note = "%s via %s" % (rule, note)
            rule = "second-order-injection"
        elif self.stored_sources is not None:
            return                       # second pass reports only second-order flows
        if self.enabled is not None and rule not in self.enabled:
            return
        o = self.origins[oid]
        # Where the request data enters the vulnerable path. When the source is
        # in a different file than where the flow was detected (an included
        # page whose variable is echoed by the including template), report it
        # at the source: that is the line to fix, and the same file a reviewer
        # opened.
        # Only for include flows: a value returned by a function in another file
        # is reported where it is used (the helper itself is not the bug).
        src_unit = self.units.get(self.origin_unit.get(root))
        if o.file != fi.rel and src_unit is not None and src_unit.kind == "file":
            file, line, col = o.file, o.line, o.col
        else:
            file, line, col = fi.rel, node.line, node.col
        key = (rule, file, line)
        if key in self.findings:
            return
        trace = [{"file": o.file, "line": o.line, "column": o.col, "note": "source: " + o.desc}]
        for h in o.hops:
            trace.append({"file": h[1], "line": h[2], "column": h[3], "note": h[0]})
        for h in steps:
            trace.append({"file": h[1], "line": h[2], "column": h[3], "note": h[0]})
        self.findings[key] = Finding(rule, file, line, col, _squash(trace), note, self.root_unit(oid))

    # ------------------------------------------------------------------ run
    def run(self):
        p = self.p
        units = [r for r in p.iter_functions() if not self.skip(r.file)]
        self.units = {r.key: r for r in units}
        self._prepass(units)
        order = self._scc_order(units)
        work = []
        for comp in order:
            for _ in range(3):
                changed = False
                for key in comp:
                    if self._analyse(key):
                        changed = True
                if not changed or len(comp) == 1:
                    break
        # worklist for late changes (property stores, globals, file envs)
        work = [k for k in self._dirty]
        self._dirty = set()
        limit = self.MAX_ANALYSES_FACTOR * max(1, len(units))
        seen_rounds = 0
        while work and self.analyses < limit and seen_rounds < 6:
            seen_rounds += 1
            nxt = set()
            for key in work:
                if key in self.units and self._analyse(key):
                    for e in (p.callgraph.inc.get(key, []) if p.callgraph else []):
                        if e.caller in self.units:
                            nxt.add(e.caller)
            nxt |= self._dirty
            self._dirty = set()
            work = sorted(nxt)
        self._templates()
        self._wp_authz()
        return list(self.findings.values())

    _dirty = set()

    def _scc_order(self, units):
        """Tarjan (iterative): SCCs of the analysed units, callee-first."""
        cg = self.p.callgraph
        keys = [u.key for u in units]
        known = set(keys)
        succ = {}
        for k in keys:
            out = []
            for e in (cg.out.get(k, []) if cg else []):
                if e.callee in known and e.kind != "defines":
                    out.append(e.callee)
            succ[k] = out
        index, low, onstack, stack, comps = {}, {}, set(), [], []
        counter = [0]
        for root in keys:
            if root in index:
                continue
            work = [(root, 0)]
            while work:
                v, i = work.pop()
                if i == 0:
                    index[v] = low[v] = counter[0]
                    counter[0] += 1
                    stack.append(v)
                    onstack.add(v)
                recurse = False
                ss = succ[v]
                while i < len(ss):
                    w = ss[i]
                    i += 1
                    if w not in index:
                        work.append((v, i))
                        work.append((w, 0))
                        recurse = True
                        break
                    if w in onstack:
                        low[v] = min(low[v], index[w])
                if recurse:
                    continue
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop()
                        onstack.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    comps.append(comp)
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[v])
        return comps

    def _prepass(self, units):
        """Entry points that need the whole project: Laravel route targets."""
        cg = self.p.callgraph
        if cg is None:
            return
        for e in cg.edges():
            if e.kind == "route":
                self.route_units.add(e.callee)

    def _analyse(self, key):
        rec = self.units.get(key)
        if rec is None:
            return False
        self.analyses += 1
        w = _Walker(self, rec)
        self.cur_unit = key
        try:
            w.run()
        except RecursionError:
            return False
        s = w.summary
        sig = s.signature()
        old = self.summaries.get(key)
        self.summaries[key] = s
        if rec.kind == "file":
            new_env = {k: v for k, v in w.exit_env.items() if v and "[" not in k and "->" not in k}
            if new_env != self.file_env.get(key):
                self.file_env[key] = new_env
                for dep in self.deps_files.get(key, ()):
                    self._dirty.add(dep)
                for name, t in new_env.items():
                    if name in self._global_names:
                        self._set_global(name, t)
        return old is None or old.sig != sig if (setattr(s, "sig", sig) or True) else False

    _global_names = set()

    def _set_fn_global(self, name, t):
        """Values functions assign to `global $x` (read at file scope)."""
        cur = self.fn_globals.get(name, EMPTY)
        new = t_union(cur, {k: v for k, v in t.items() if isinstance(k, int)})
        if new != cur:
            self.fn_globals[name] = new
            for dep in self.deps_globals.get(name, ()):
                self._dirty.add(dep)

    def _set_global(self, name, t):
        cur = self.globals.get(name, EMPTY)
        new = t_union(cur, {k: v for k, v in t.items() if isinstance(k, int)})
        if new != cur:
            self.globals[name] = new
            for dep in self.deps_globals.get(name, ()):
                self._dirty.add(dep)

    def add_prop(self, cls, prop, t):
        real = {k: v for k, v in t.items() if isinstance(k, int)}
        if not real or not cls:
            return
        key = (cls.lower(), prop)
        cur = self.props.get(key, EMPTY)
        new = t_union(cur, real)
        if new != cur:
            self.props[key] = new
            for dep in self.deps_props.get(key, ()):
                self._dirty.add(dep)

    def read_prop(self, cls, prop, reader):
        out = EMPTY
        for c in self.p.ancestors(cls) if cls else []:
            key = (c.fq.lower(), prop)
            self.deps_props.setdefault(key, set()).add(reader)
            v = self.props.get(key)
            if v:
                out = t_union(out, v)
        return out

    # ------------------------------------------------------------ templates
    def bind_template(self, engine, name, binds, fi, node):
        if not binds:
            return
        k = (engine, name)
        cur = self.templates.setdefault(k, {})
        for var, t in binds.items():
            real = {o: v for o, v in t.items() if isinstance(o, int) and "xss" in v}
            if real:
                cur[var] = t_union(cur.get(var, EMPTY), real)
                self.template_sites.setdefault((engine, name, var), (fi, node))

    def _templates(self):
        root = self.p.root
        for (engine, name), binds in self.templates.items():
            paths = LV.view_template_paths(root, name) if engine == "blade" else SF.twig_template_paths(root, name)
            for path in paths:
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                if engine == "blade":
                    outs = [(ln, vars_) for ln, _e, vars_, _d in LV.blade_raw_echoes(path)]
                    rule = "blade-raw"
                else:
                    outs = [(ln, [v]) for ln, v in SF.twig_raw_outputs(path)]
                    rule = "twig-raw"
                for ln, vars_ in outs:
                    for v in vars_:
                        t = binds.get(v)
                        if not t:
                            continue
                        oid = next(iter(t))
                        fi, node = self.template_sites[(engine, name, v)]
                        node_t = _FakeNode(ln, 1)
                        steps = (("passed to template %s as $%s" % (name, v), fi.rel, node.line, node.col),
                                 ("printed unescaped", rel, ln, 1))
                        tfi = _FakeFile(rel)
                        o = self.origins[oid]
                        key = (rule, rel, ln)
                        if key in self.findings or (self.enabled is not None and rule not in self.enabled):
                            continue
                        trace = [{"file": o.file, "line": o.line, "column": o.col, "note": "source: " + o.desc}]
                        trace += [{"file": h[1], "line": h[2], "column": h[3], "note": h[0]} for h in o.hops]
                        trace += [{"file": h[1], "line": h[2], "column": h[3], "note": h[0]} for h in steps]
                        self.findings[key] = Finding(rule, tfi.rel, node_t.line, 1, trace,
                                                     "Request data reaches an unescaped template output.")
                        break
        # Blade files that print request data directly ({!! request('x') !!})
        if self.enabled is None or "blade-raw" in self.enabled:
            for base in ("resources/views",):
                top = os.path.join(root, base)
                if not os.path.isdir(top):
                    continue
                for d, _dirs, fs in os.walk(top):
                    for f in fs:
                        if not f.endswith(".blade.php"):
                            continue
                        path = os.path.join(d, f)
                        rel = os.path.relpath(path, root).replace(os.sep, "/")
                        for ln, expr, _v, direct in LV.blade_raw_echoes(path):
                            if direct and ("blade-raw", rel, ln) not in self.findings:
                                self.findings[("blade-raw", rel, ln)] = Finding(
                                    "blade-raw", rel, ln, 1,
                                    [{"file": rel, "line": ln, "column": 1, "note": "source and sink: {!! %s !!}" % expr[:80]}],
                                    "Request data is printed unescaped with {!! !!}.")

    # ---------------------------------------------------------- WP authz
    def _reach(self, keys, depth=4):
        cg = self.p.callgraph
        seen, frontier = set(), list(keys)
        for _ in range(depth + 1):
            nxt = []
            for k in frontier:
                if k in seen:
                    continue
                seen.add(k)
                for e in (cg.out.get(k, []) if cg else []):
                    if e.callee in self.units and e.kind not in ("include",):
                        nxt.append(e.callee)
            frontier = nxt
        return seen

    def _wp_authz(self):
        en = self.enabled
        nopriv = set()
        for typ, keys, fi, node, action in self.ajax_hooks:
            if typ == "nopriv":
                nopriv.update(keys)
        for typ, keys, fi, node, action in self.ajax_hooks:
            if not keys:
                continue
            reach = self._reach(keys)
            sums = [self.summaries[k] for k in reach if k in self.summaries]
            writes = [w for s in sums for w in s.writes]
            if not writes:
                continue
            guards = any(s.guards for s in sums)
            nonce = any(s.nonce for s in sums)
            cb = self.units[keys[0]]
            where = "%s:%d" % (cb.file.rel, (cb.node.line if cb.node is not None else 1))
            name = cb.name or keys[0]
            if typ == "nopriv" and not guards:
                self._authz_finding("wp-nopriv-ajax-no-auth", fi, node,
                                    "wp_ajax_nopriv_ handler %s() (%s) writes without nonce/capability check."
                                    % (name, where), writes)
            elif typ == "adminpost" and not nonce:
                self._authz_finding("wp-admin-post-no-nonce", fi, node,
                                    "admin-post handler %s() (%s) writes without a nonce check (cross-site request "
                                    "forgery)." % (name, where), writes)
            elif typ == "priv" and not (set(keys) & nopriv) and not nonce:
                self._authz_finding("wp-ajax-no-nonce", fi, node,
                                    "AJAX handler %s() (%s) writes without a nonce check." % (name, where), writes)
        for keys, fi, node in self.rest_open:
            reach = self._reach(keys)
            writes = [w for k in reach if k in self.summaries for w in self.summaries[k].writes]
            if writes:
                cb = self.units[keys[0]]
                self._authz_finding("wp-rest-open-write", fi, node,
                                    "REST callback %s() (%s:%d) writes but permission_callback is __return_true."
                                    % (cb.name or keys[0], cb.file.rel, cb.node.line if cb.node is not None else 1),
                                    writes)

    def _authz_finding(self, rule, fi, node, msg, writes):
        if self.enabled is not None and rule not in self.enabled:
            return
        key = (rule, fi.rel, node.line)
        if key in self.findings:
            return
        trace = [{"file": fi.rel, "line": node.line, "column": node.col, "note": "handler registered"}]
        for what, f, ln in writes[:3]:
            trace.append({"file": f, "line": ln, "column": 1, "note": "state change: " + what})
        self.findings[key] = Finding(rule, fi.rel, node.line, node.col, trace, msg)


class _FakeNode:
    def __init__(self, line, col):
        self.line = line
        self.col = col


class _FakeFile:
    def __init__(self, rel):
        self.rel = rel


# ===================================================================== walker
class _Walker:
    def __init__(self, eng, rec):
        self.e = eng
        self.p = eng.p
        self.rec = rec
        self.fi = rec.file
        self.ctx = rec.ctx
        self.cls = rec.cls
        self.types = Types(self.p, rec)
        self.summary = Summary()
        self.exit_env = {}
        self.globals_here = set()
        self.lit_arrays = set()        # vars holding a literal array of safe strings
        self._lit_array_nodes = {}     # var -> the literal Array node it holds
        self.closed_arrays = set()     # vars holding an array whose keys are all known literals
        self._prop_written = {}        # $this properties assigned in this function
        self._env = None               # env/tenv of the statement being walked (for call arguments)
        self._tenv = None
        self.ret_seen = False
        self._returns = []             # taint of each return statement
        self.unit_label = self._label()

    def _label(self):
        r = self.rec
        if r.kind == "method":
            return "%s::%s()" % (r.cls.rsplit("\\", 1)[-1] if r.cls else "?", r.name)
        if r.kind == "function":
            return "%s()" % r.name
        if r.kind == "closure":
            return "closure at %s:%d" % (r.file.rel, r.node.line if r.node is not None else 0)
        return r.file.rel

    # ------------------------------------------------------------- set-up
    def run(self):
        env = {}
        tenv = self.types.initial()
        rec = self.rec
        is_route = rec.key in self.e.route_units or (rec.kind == "method" and rec.node is not None
                                                     and SF.route_attribute(rec.node))
        for i, prm in enumerate(rec.params or []):
            t = {("p", i): SRC_KINDS | {"mass"}}
            # int/float/bool parameters: PHP coerces or rejects anything else
            # (TypeError on a non-numeric string), so nothing injectable arrives
            if prm.type is not None and prm.type.names and all(
                    n.lower() in _PARAM_SAFE_TYPES for n in prm.type.names):
                t = EMPTY
            if is_route and self._route_param_tainted(prm, tenv):
                oid = self.e.new_origin("route parameter $%s of %s" % (prm.name, self.unit_label), self.fi, prm)
                t = t_union(t, {oid: SRC_KINDS})
            env[prm.name] = t
        if rec.kind == "closure" and rec.node is not None:
            cap = self.e.closure_env.get(rec.key, {})
            self.e.deps_closures.setdefault(rec.key, set())
            for u in rec.node.get("uses") or []:
                nm = u.get("name") if hasattr(u, "get") else None
                if isinstance(nm, str):
                    env.setdefault(nm, cap.get(nm, EMPTY))
        self.block(rec.body, env, tenv)
        self.exit_env = env
        self._export_returns()

    def _export_returns(self):
        """A function is a source for its callers only when every return hands
        back request data, and never for $_SERVER values (paths, hosts and
        URIs a helper typically formats for links). Parameter pass-through is
        kept as is."""
        if self.rec.kind == "file" or not self._returns:
            return
        every = all(any(isinstance(o, int) for o in t) for t in self._returns)
        ret = {}
        for o, v in self.summary.ret.items():
            if isinstance(o, int):
                if not every:
                    continue
                root = o
                while self.e.origins[root].parent is not None:
                    root = self.e.origins[root].parent
                if self.e.origins[root].desc.startswith("$_SERVER"):
                    continue
            ret[o] = v
        self.summary.ret = ret

    def _capture(self, node, env):
        """A closure's `use ($x)` copies the parent's value at creation time."""
        key = self.p._node_keys.get(id(node)) if hasattr(self.p, "_node_keys") else None
        if not key:
            return
        cap = {}
        for u in node.get("uses") or []:
            nm = u.get("name") if hasattr(u, "get") else None
            if isinstance(nm, str) and env.get(nm):
                real = {o: v for o, v in env[nm].items() if isinstance(o, int)}
                if real:
                    cap[nm] = real
        if cap and cap != self.e.closure_env.get(key):
            self.e.closure_env[key] = cap
            self.e._dirty.add(key)

    def _route_param_tainted(self, prm, tenv):
        if prm.type is None:
            return True
        names = [n.lower() for n in prm.type.names]
        if any(n in _PARAM_SAFE_TYPES for n in names):
            return False
        if any(n in ("string", "mixed") for n in names):
            return True
        # typed with a class: injected service or route model binding
        return False

    # --------------------------------------------------------- statements
    def block(self, body, env, tenv):
        """Walk statements; returns True when the block always ends the request
        (or leaves the enclosing loop/function)."""
        for s in body or []:
            if s is None:
                continue
            if self.stmt(s, env, tenv):
                return True
        return False

    def stmt(self, s, env, tenv):
        k = s.kind
        d = s.__dict__.get("doc")
        if d:
            self.types.doc_vars(d, tenv)
        if k == "ExprStmt":
            x = s.expr
            self.expr(x, env, tenv)
            if x is not None:
                if x.kind == "Exit":
                    return True
                if x.kind == "Call" and x.func.kind == "Name" and _lname(x.func.name) in B.EXIT_FNS:
                    return True
                if x.kind == "Throw":
                    return True
                if x.kind == "Call" and x.func.kind == "Name":
                    self._statement_guard(x, env)
            return False
        if k == "Echo":
            for ex in s.exprs:
                t = self.expr(ex, env, tenv)
                self.sink(t, "xss", B.ECHO_RULE, ex, "echo")
            return False
        if k == "Return":
            t = self.expr(s.expr, env, tenv) if s.expr is not None else EMPTY
            self._returns.append(t)
            self.summary.ret = t_union(self.summary.ret, t)
            return True
        if k == "If":
            return self.if_(s, env, tenv)
        if k in ("While", "DoWhile", "For"):
            self.loop(s, env, tenv)
            return False
        if k == "Foreach":
            self.foreach(s, env, tenv)
            return False
        if k == "Switch":
            self.switch(s, env, tenv)
            return False
        if k == "Try":
            self.try_(s, env, tenv)
            return False
        if k in ("Block", "Declare"):
            return self.block(s.body or [], env, tenv)
        if k == "Global":
            for v in s.vars:
                if v.kind == "Var" and isinstance(v.name, str):
                    name = v.name
                    self.globals_here.add(name)
                    self.e._global_names.add(name)
                    self.e.deps_globals.setdefault(name, set()).add(self.rec.key)
                    env[name] = self.e.globals.get(name, EMPTY)
            return False
        if k == "Unset":
            for v in s.vars:
                key = self.key(v)
                if key:
                    env[key] = EMPTY
            return False
        if k in ("Break", "Continue"):
            return True
        if k in ("Throw",):
            return True
        if k in _SKIP_KINDS or k in ("Namespace", "Use", "Const", "InlineHTML", "HaltCompiler", "Label",
                                     "Goto", "Static"):
            if k == "Namespace" and s.get("body"):
                return self.block(s.body, env, tenv)
            if k == "Static":
                for sv in s.vars:
                    if sv.default is not None:
                        env[sv.name] = self.expr(sv.default, env, tenv)
            return False
        for ch in s.children():
            if ch.kind not in _SKIP_KINDS:
                self.expr(ch, env, tenv)
        return False

    def if_(self, s, env, tenv):
        base = env
        self.expr(s.cond, env, tenv)
        branches = []        # (env, tenv, exits)
        cur_env = dict(env)
        cur_t = dict(tenv)
        conds = [(s.cond, s.body)] + [(ei.cond, ei.body) for ei in (s.elifs or [])]
        for i, (cond, body) in enumerate(conds):
            if i > 0:
                self.expr(cond, cur_env, cur_t)
            be = self.apply_guards(dict(cur_env), self.guards(cond, True, cur_env))
            bt = dict(cur_t)
            ex = self.block(body, be, bt)
            branches.append((be, bt, ex))
            cur_env = self.apply_guards(cur_env, self.guards(cond, False, cur_env))
        if s.else_ is not None:
            be, bt = dict(cur_env), dict(cur_t)
            ex = self.block(s.else_, be, bt)
            branches.append((be, bt, ex))
        else:
            branches.append((cur_env, cur_t, False))
        live = [b for b in branches if not b[2]]
        if not live:
            # every branch leaves: what follows is unreachable from here
            env.clear()
            env.update(branches[-1][0])
            return True
        merged, mt = live[0][0], live[0][1]
        for be, bt, _ in live[1:]:
            merged = env_join(merged, be)
            mt = tjoin(mt, bt)
        env.clear()
        env.update(merged)
        tenv.clear()
        tenv.update(mt)
        return False

    def loop(self, s, env, tenv):
        for part in ("init", "cond", "step"):
            v = s.get(part)
            for x in (v if isinstance(v, list) else [v]):
                if x is not None:
                    self.expr(x, env, tenv)
        e1, t1 = dict(env), dict(tenv)
        if s.kind == "While" and s.get("cond") is not None:
            e1 = self.apply_guards(e1, self.guards(s.cond, True, e1))
        self.block(s.body, e1, t1)
        merged = env_join(env, e1)
        if merged != env:
            e2, t2 = dict(merged), dict(tjoin(tenv, t1))
            self.block(s.body, e2, t2)
            merged = env_join(merged, e2)
        env.clear()
        env.update(merged)
        tenv.update(tjoin(tenv, t1))

    def foreach(self, s, env, tenv):
        st = self.expr(s.subject, env, tenv)
        e1, t1 = dict(env), dict(tenv)
        self.types.foreach(s, t1)
        # keys of request arrays are attacker-controlled too
        if s.key is not None:
            self.assign_target(s.key, st, e1, t1, s)
        if s.value is not None:
            self.assign_target(s.value, st, e1, t1, s)
        self.block(s.body, e1, t1)
        merged = env_join(env, e1)
        if merged != env:
            e2, t2 = dict(merged), dict(t1)
            if s.value is not None:
                self.assign_target(s.value, st, e2, t2, s)
            self.block(s.body, e2, t2)
            merged = env_join(merged, e2)
        env.clear()
        env.update(merged)
        tenv.update(tjoin(tenv, t1))

    def switch(self, s, env, tenv):
        self.expr(s.cond, env, tenv)
        merged = None
        fall_env, fall_t = None, None
        has_default = False
        for c in s.cases:
            if c.test is None:
                has_default = True
            else:
                self.expr(c.test, env, tenv)
            ce = dict(env) if fall_env is None else env_join(env, fall_env)
            ct = dict(tenv) if fall_t is None else tjoin(tenv, fall_t)
            # case 'literal': the subject equals that literal inside this case
            # (only when not reached by falling through from another case)
            if c.test is not None and c.test.kind in ("String", "Int", "Float") and fall_env is None:
                sk = self.key(s.cond)
                if sk is None and s.cond.kind == "Call" and s.cond.func.kind == "Name" and s.cond.args and \
                        _lname(s.cond.func.name) in _CMP_WRAPPERS:
                    sk = self.key(s.cond.args[0].value)
                if sk and sk in ce:
                    ce[sk] = EMPTY
            ex = self.block(c.body, ce, ct)
            ends = bool(c.body) and c.body[-1] is not None and c.body[-1].kind in ("Break", "Return", "Continue")
            if ex and not ends:
                fall_env, fall_t = None, None
                continue
            merged = ce if merged is None else env_join(merged, ce)
            fall_env, fall_t = (None, None) if ends else (ce, ct)
        if merged is None or not has_default:
            merged = env if merged is None else env_join(env, merged)
        env.clear()
        env.update(merged)

    def try_(self, s, env, tenv):
        before = dict(env)
        self.block(s.body, env, tenv)
        after = dict(env)
        for c in s.catches:
            ce, ct = env_join(before, after), dict(tenv)
            self.block(c.body, ce, ct)
            env.update(env_join(env, ce))
        if s.finally_:
            self.block(s.finally_, env, tenv)

    def _statement_guard(self, c, env):
        name = _lname(c.func.name)
        idx = B.STATEMENT_GUARDS.get(name)
        if idx is not None and len(c.args) > idx:
            for v in self.vars_in(c.args[idx].value):
                env[v] = EMPTY
        if name in WP.WP_GUARDS:
            self.summary.guards = True
            if name in WP.WP_NONCES:
                self.summary.nonce = True

    # --------------------------------------------------------------- guards
    def key(self, e):
        if e is None:
            return None
        if e.kind == "Var" and isinstance(e.name, str):
            return e.name
        if e.kind == "ArrayDim" and e.var.kind == "Var" and isinstance(e.var.name, str) and e.dim is not None \
                and e.dim.kind in ("String", "Int"):
            return "%s[%s]" % (e.var.name, e.dim.value)
        if e.kind == "PropFetch" and isinstance(e.name, str) and e.obj.kind == "Var" and e.obj.name == "this":
            return "this->" + e.name
        return None

    def vars_in(self, e):
        out = set()
        if e is None:
            return out
        stack = [e]
        while stack:
            x = stack.pop()
            if x is None:
                continue
            k = self.key(x)
            if k:
                out.add(k)
                if "[" in k:
                    out.add(k.split("[", 1)[0])
            stack.extend(x.children())
        return out

    def _descends(self, oid, roots):
        o = self.e.origins
        while oid is not None:
            if oid in roots:
                return True
            oid = o[oid].parent
        return False

    def apply_guards(self, env, keys):
        roots = set()
        for k in keys:
            for o in env.get(k, EMPTY):
                if isinstance(o, int):
                    roots.add(o)
        if roots:
            # values derived from a checked variable earlier in the function are
            # as safe as the variable itself
            for v, t in list(env.items()):
                if t and any(isinstance(o, int) and o not in roots and self._descends(o, roots) for o in t):
                    env[v] = {o: x for o, x in t.items()
                              if not (isinstance(o, int) and o not in roots and self._descends(o, roots))}
        for k in keys:
            env[k] = EMPTY
            if "[" not in k:
                # the whole value is now known-safe: drop its keyed parts too
                for kk in [x for x in env if x.startswith(k + "[")]:
                    env[kk] = EMPTY
        return env

    def _safe_list(self, e):
        if e is None:
            return False
        if e.kind == "Array":
            for it in e.items:
                v = it.value if it is not None else None
                if v is None:
                    return False
                if v.kind == "String":
                    if re.match(r"^\s*[-+]?\d", v.value or ""):
                        return False
                elif v.kind not in ("Int",):
                    return False
            return True
        if e.kind == "Var" and isinstance(e.name, str):
            return e.name in self.lit_arrays
        if e.kind in ("ClassConst", "StaticProp"):
            return True
        return False

    def _nonnumeric_strings(self, e):
        """A literal array (or a var holding one) of non-numeric string literals only."""
        if e is not None and e.kind == "Var" and isinstance(e.name, str):
            e = self._lit_array_nodes.get(e.name)
        if e is None or e.kind != "Array" or not e.items:
            return False
        for it in e.items:
            v = it.value if it is not None else None
            if v is None or v.kind != "String" or re.fullmatch(r"\s*[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?\s*", v.value or ""):
                return False
        return True

    def _sole_var(self, e):
        """'prefix_' . $x . '_suffix' -> key of $x when it is the only variable part:
        if the whole string is in a fixed list, $x is limited to a fixed set too."""
        if e is None or not (e.kind == "BinOp" and e.op == "."):
            return None
        parts = []
        self._flatten(e, parts)
        keys = [self.key(x) for x in parts if x.kind not in ("String", "Int")]
        if len(keys) == 1 and keys[0] and all(x.kind in ("String", "Int") or self.key(x) for x in parts):
            return keys[0]
        return None

    def guards(self, cond, truth, env):
        """Keys that are safe when `cond` evaluates to `truth`."""
        if cond is None:
            return set()
        k = cond.kind
        if k == "UnaryOp" and cond.op == "!":
            return self.guards(cond.expr, not truth, env)
        if k == "BinOp":
            op = cond.op.lower()
            if op in ("&&", "and"):
                a, b = self.guards(cond.left, truth, env), self.guards(cond.right, truth, env)
                return (a | b) if truth else (a & b)
            if op in ("||", "or"):
                a, b = self.guards(cond.left, truth, env), self.guards(cond.right, truth, env)
                return (a & b) if truth else (a | b)
            if op in ("===", "==", "!==", "!=", "<>"):
                pos = op in ("===", "==")
                l, r = cond.left, cond.right
                for a, b in ((l, r), (r, l)):
                    # 0 === validate_file($x)
                    if a.kind in ("Int",) and str(a.value) == "0" and b.kind == "Call" and b.func.kind == "Name" \
                            and _lname(b.func.name) in B.VALIDATORS and b.args:
                        if pos == truth:
                            return self.vars_in(b.args[0].value)
                        return set()
                    # $x === 'literal', strtolower($x) == 'literal'
                    if a.kind in ("String", "Int", "Float"):
                        bk = self.key(b)
                        if bk is None and b.kind == "Call" and b.func.kind == "Name" and b.args and \
                                _lname(b.func.name) in _CMP_WRAPPERS:
                            bk = self.key(b.args[0].value)
                        if bk:
                            return {bk} if pos == truth else set()
                    if a.kind == "Name" and _lname(a.name) in ("true", "false", "null") and b.kind == "Call":
                        inner = self.guards(b, (pos == truth) == (_lname(a.name) == "true"), env)
                        if inner:
                            return inner
                return set()
            if op in ("<", ">", "<=", ">="):
                return set()
            return set()
        if k == "Call" and cond.func.kind == "Name":
            name = _lname(cond.func.name)
            args = cond.args
            if name in B.GUARD_FNS or name.startswith("ctype_"):
                return {x for x in [self.key(args[0].value)] if x} if truth and args else set()
            if name == "preg_match" and len(args) >= 2 and args[0].value.kind == "String":
                pat = args[0].value.value
                if truth and B.whitelist_pattern(pat):
                    return {x for x in [self.key(args[1].value)] if x}
                if not truth and B.negclass_pattern(pat):
                    return {x for x in [self.key(args[1].value)] if x}
                return set()
            if name == "in_array" and len(args) >= 2 and truth:
                strict = len(args) > 2 and args[2].value.kind == "Name" and _lname(args[2].value.name) == "true"
                # Loose in_array() is a whitelist only against non-numeric string
                # literals (string-to-string comparison is exact there); against
                # numbers it is bypassable ("0 or 1" == 0 in PHP 7).
                if (strict and (self._safe_list(args[1].value) or args[1].value.kind in ("Array", "Var"))) or \
                        (not strict and self._nonnumeric_strings(args[1].value)):
                    return {x for x in [self.key(args[0].value) or self._sole_var(args[0].value)] if x}
                return set()
            if name == "array_key_exists" and len(args) >= 2 and truth:
                return {x for x in [self.key(args[0].value)] if x}
            if name in B.VALIDATORS and args:
                return self.vars_in(args[0].value) if not truth else set()
            if name == "is_wp_error" and args and args[0].value.kind == "Call" and \
                    args[0].value.func.kind == "Name" and _lname(args[0].value.func.name) in B.VALIDATORS:
                inner = args[0].value
                return self.vars_in(inner.args[0].value) if (not truth and inner.args) else set()
            if name == "hash_equals" and len(args) >= 2 and truth:
                return self.vars_in(args[0].value) | self.vars_in(args[1].value)
            if name in WP.WP_GUARDS:
                self.summary.guards = True
                if name in WP.WP_NONCES:
                    self.summary.nonce = True
            return set()
        if k == "Isset" and truth:
            # isset($allowed[$v]): $v is a key of a fixed map (not of request data)
            out = set()
            for v in cond.vars or []:
                if v is not None and v.kind == "ArrayDim" and v.dim is not None and not (
                        v.var.kind == "Var" and isinstance(v.var.name, str) and v.var.name in B.SUPERGLOBALS):
                    x = self.key(v.dim) or self._sole_var(v.dim)
                    if x:
                        out.add(x)
            return out
        if k == "Instanceof":
            return set()
        if k == "Assign":
            return self.guards(cond.value, truth, env) if self.key(cond.target) is None else set()
        return set()

    # --------------------------------------------------------- assignment
    def assign_target(self, tgt, t, env, tenv, node, value=None):
        k = tgt.kind
        if k == "Var" and isinstance(tgt.name, str):
            if t and value is not None and value.kind != "Var":
                hop = ("assigned to $%s" % tgt.name, self.fi.rel, node.line, node.col)
                t = {(self.e.derive(o, hop) if isinstance(o, int) else o): v for o, v in t.items()}
                self._last_assigned = tgt.name
            env[tgt.name] = t
            for kk in [x for x in env if x.startswith(tgt.name + "[")]:
                del env[kk]
            self.closed_arrays.discard(tgt.name)
            if value is not None and value.kind == "Array" and value.items and all(
                    it is not None and not it.unpack and it.key is not None and it.key.kind in ("String", "Int")
                    for it in value.items):
                for it in value.items:
                    env["%s[%s]" % (tgt.name, it.key.value)] = self.expr_quiet(it.value, env, tenv)
                self.closed_arrays.add(tgt.name)
            if value is not None:
                self.types.assign(tgt, value, tenv)
                if self._safe_list(value) and value.kind == "Array":
                    self.lit_arrays.add(tgt.name)
                    self._lit_array_nodes[tgt.name] = value
                else:
                    self.lit_arrays.discard(tgt.name)
                    self._lit_array_nodes.pop(tgt.name, None)
            if tgt.name in self.globals_here:
                self.e._set_global(tgt.name, t)
                if self.rec.kind != "file":
                    self.e._set_fn_global(tgt.name, t)
            return
        if k == "ArrayDim":
            base = tgt.var
            # $_SESSION['k'] = <request data>: reads of the same literal key
            # elsewhere are second-order sources (dynamic keys: nothing)
            if (base.kind == "Var" and base.name == "_SESSION" and tgt.dim is not None
                    and tgt.dim.kind == "String" and any(isinstance(o, int) for o in (t or {}))):
                self.e.stored.setdefault(("session", tgt.dim.value), (self.fi.rel, node.line))
            kk = self.key(tgt)
            if kk:
                env[kk] = t
            elif base.kind == "Var" and isinstance(base.name, str):
                self.closed_arrays.discard(base.name)
            root = base
            while root.kind in ("ArrayDim",):
                root = root.var
            rk = self.key(root)
            if rk:
                env[rk] = t_union(env.get(rk, EMPTY), t)
            elif root.kind == "PropFetch":
                self.assign_target(root, t_union(self.expr_quiet(root, env, tenv), t), env, tenv, node)
            return
        if k == "PropFetch" and isinstance(tgt.name, str):
            if tgt.obj.kind == "Var" and tgt.obj.name == "this":
                env["this->" + tgt.name] = t
                self._prop_written[tgt.name] = True
                if value is not None:
                    self.types.assign(tgt, value, tenv)
                self.e.add_prop(self.cls, tgt.name, t)
                sym = {o: v for o, v in t.items() if not isinstance(o, int)}
                if sym:
                    cur = self.summary.propw.get(tgt.name, EMPTY)
                    self.summary.propw[tgt.name] = t_union(cur, sym)
            else:
                rk = self.key(tgt.obj)
                if rk:
                    env[rk] = t_union(env.get(rk, EMPTY), t)
            return
        if k == "StaticProp" and isinstance(tgt.name, str) and tgt.cls.kind == "Name":
            cls = self.p.resolve_class(tgt.cls.name, self.ctx)
            self.e.add_prop(cls, tgt.name, t)
            return
        if k in ("List", "Array"):
            for it in tgt.items:
                if it is None or it.value is None:
                    continue
                self.assign_target(it.value, t, env, tenv, node)
            return

    # --------------------------------------------------------- expressions
    def expr_quiet(self, e, env, tenv):
        return self.expr(e, env, tenv)

    def expr(self, e, env, tenv):
        if e is None:
            return EMPTY
        self._env, self._tenv = env, tenv
        k = e.kind
        if k == "Closure":
            self._capture(e, env)
            return EMPTY
        if k in ("String", "Int", "Float", "MagicConst", "Name", "ClassConst", "ArrowFn",
                 "Isset", "Empty", "Instanceof", "InlineHTML"):
            if k in ("Isset", "Empty"):
                for v in (e.vars if k == "Isset" else [e.expr]):
                    self.expr(v, env, tenv)
            if k == "Instanceof":
                self.expr(e.expr, env, tenv)
            return EMPTY
        if k == "Var":
            if isinstance(e.name, str):
                if e.name in B.SUPERGLOBALS:
                    return self.source("$_%s" % e.name[1:] if e.name.startswith("_") else "$" + e.name, e)
                if e.name == "GLOBALS":
                    return EMPTY
                if e.name not in env and self.rec.kind == "file":
                    # file scope is global scope: a function's `global $x; $x = ...` lands here
                    self.e.deps_globals.setdefault(e.name, set()).add(self.rec.key)
                    return self.e.fn_globals.get(e.name, EMPTY)
                return env.get(e.name, EMPTY)
            return self.expr(e.name, env, tenv)
        if k == "ArrayDim":
            return self.array_dim(e, env, tenv)
        if k == "PropFetch":
            return self.prop_fetch(e, env, tenv)
        if k == "StaticProp":
            if isinstance(e.name, str) and e.cls.kind == "Name":
                cls = self.p.resolve_class(e.cls.name, self.ctx)
                return self.e.read_prop(cls, e.name, self.rec.key)
            return EMPTY
        if k == "Interp":
            return self.concat(e.parts, env, tenv)
        if k == "ShellExec":
            t = self.concat(e.parts, env, tenv)
            self.sink(t, "cmd", B.BACKTICK_RULE, e, "shell command (backticks)")
            return t
        if k == "BinOp":
            op = e.op
            if op == ".":
                parts = []
                self._flatten(e, parts)
                return self.concat(parts, env, tenv)
            if op == "??":
                return t_union(self.expr(e.left, env, tenv), self.expr(e.right, env, tenv))
            if op in ("&&", "||", "and", "or", "xor"):
                self.expr(e.left, env, tenv)
                self.expr(e.right, env, tenv)
                return EMPTY
            self.expr(e.left, env, tenv)
            self.expr(e.right, env, tenv)
            return EMPTY
        if k == "UnaryOp":
            self.expr(e.expr, env, tenv)
            return EMPTY
        if k == "Cast":
            t = self.expr(e.expr, env, tenv)
            if _lname(e.type) in B.INT_CASTS:
                return EMPTY
            return t
        if k in ("Assign", "AssignRef"):
            return self.assign(e, env, tenv)
        if k == "IncDec":
            return EMPTY
        if k == "Ternary":
            c = self.expr(e.cond, env, tenv)
            te = self.apply_guards(dict(env), self.guards(e.cond, True, env))
            ee = self.apply_guards(dict(env), self.guards(e.cond, False, env))
            a = self.expr(e.then, te, tenv) if e.then is not None else c
            b = self.expr(e.else_, ee, tenv)
            # assignments inside the branches ($c ? $x = A : $x = B) survive
            merged = env_join(te, ee)
            for kk, vv in merged.items():
                if env.get(kk) is not vv:
                    env[kk] = t_union(env.get(kk, EMPTY), vv) if kk not in te or kk not in ee else vv
            return t_union(a, b)
        if k == "Match":
            self.expr(e.subject, env, tenv)
            out = EMPTY
            for arm in e.arms:
                for c in arm.conds or []:
                    self.expr(c, env, tenv)
                out = t_union(out, self.expr(arm.body, env, tenv))
            return out
        if k in ("Array", "List"):
            out = EMPTY
            for it in e.items:
                if it is None:
                    continue
                if it.key is not None:
                    out = t_union(out, self.expr(it.key, env, tenv))
                out = t_union(out, self.expr(it.value, env, tenv))
            return out
        if k == "Call":
            return self.call(e, env, tenv)
        if k == "MethodCall":
            return self.method_call(e, env, tenv)
        if k == "StaticCall":
            return self.static_call(e, env, tenv)
        if k == "New":
            return self.new(e, env, tenv)
        if k == "Include":
            t = self.expr(e.expr, env, tenv)
            self.sink(t, "incl", B.INCLUDE_RULE, e, e.type)
            site = getattr(e, "site", None)
            if site is not None:
                for target in site.targets:
                    fk = "file:" + os.path.relpath(target, self.p.root)
                    self.e.deps_files.setdefault(fk, set()).add(self.rec.key)
                    fenv = self.e.file_env.get(fk)
                    if fenv:
                        frel = fk[5:]
                        orig = self.e.origins
                        for name, tv in fenv.items():
                            # only what the included file itself read from the
                            # request; values it got from us or from globals are
                            # already here (and may have been checked since)
                            own = {o: v for o, v in tv.items() if isinstance(o, int) and orig[o].file == frel}
                            if own:
                                env[name] = t_union(env.get(name, EMPTY), own)
            return EMPTY
        if k == "Eval":
            t = self.expr(e.expr, env, tenv)
            self.sink(t, "code", B.EVAL_RULE, e, "eval")
            return EMPTY
        if k == "Exit":
            if e.expr is not None:
                t = self.expr(e.expr, env, tenv)
                if e.expr.kind not in ("Int",):
                    self.sink(t, "xss", B.ECHO_RULE, e, e.get("word") or "exit")
            return EMPTY
        if k == "Print":
            t = self.expr(e.expr, env, tenv)
            self.sink(t, "xss", B.ECHO_RULE, e, "print")
            return EMPTY
        if k == "Clone":
            return self.expr(e.expr, env, tenv)
        if k == "Throw":
            self.expr(e.expr, env, tenv)
            return EMPTY
        if k in ("Yield", "YieldFrom"):
            for ch in e.children():
                self.expr(ch, env, tenv)
            return EMPTY
        if k == "Ref":
            return self.expr(e.expr, env, tenv)
        out = EMPTY
        for ch in e.children():
            if ch.kind not in _SKIP_KINDS:
                out = t_union(out, self.expr(ch, env, tenv))
        return out

    def _flatten(self, e, parts):
        if e.kind == "BinOp" and e.op == ".":
            self._flatten(e.left, parts)
            self._flatten(e.right, parts)
        else:
            parts.append(e)

    def concat(self, parts, env, tenv):
        """String building with SQL quote awareness: an escaped value (sqlq) is
        safe inside quotes and still injectable outside them."""
        out = EMPTY
        quote = None
        fixed = False          # a fixed scheme/host/path already leads the string
        for p in parts:
            if p is None:
                continue
            if p.kind == "String":
                for ch in _unescaped_quotes(p.value or ""):
                    if quote is None:
                        quote = ch
                    elif quote == ch:
                        quote = None
                v = p.value or ""
                if "/" in v or "?" in v or (out == EMPTY and "." in v):
                    fixed = True
                continue
            t = self.expr(p, env, tenv)
            if fixed:
                t = t_remove(t, {"url"})
            elif not t:
                fixed = True
            if t and any("sqlq" in v for v in t.values()):
                nt = {}
                for o, v in t.items():
                    if "sqlq" in v:
                        v = (v - {"sqlq"}) if quote else ((v - {"sqlq"}) | {"sql"})
                    if v:
                        nt[o] = v
                t = nt
            out = t_union(out, {o: v - {"mass"} for o, v in t.items() if v - {"mass"}})
        return out

    def assign(self, a, env, tenv):
        op = a.op if a.kind == "Assign" else "="
        tgt = a.target
        if op == "=":
            t = self.expr(a.value, env, tenv)
            self.assign_target(tgt, t, env, tenv, a, a.value)
            return t
        if op == ".=":
            new = self.concat([a.value], env, tenv)
            old = self.expr(tgt, env, tenv) if self.key(tgt) else EMPTY
            t = t_union(old, new)
            self.assign_target(tgt, t, env, tenv, a)
            return t
        if op == "??=":
            t = t_union(self.expr(tgt, env, tenv), self.expr(a.value, env, tenv))
            self.assign_target(tgt, t, env, tenv, a)
            return t
        self.expr(a.value, env, tenv)
        self.assign_target(tgt, EMPTY, env, tenv, a)
        return EMPTY

    def array_dim(self, e, env, tenv):
        base = e.var
        dim = e.dim
        if dim is not None:
            self.expr(dim, env, tenv)
        # $_FILES[..]['tmp_name'] / ['size'] / ['error'] are set by the server
        if dim is not None and dim.kind == "String" and dim.value in B.FILES_SAFE_KEYS:
            return EMPTY
        if base.kind == "Var" and isinstance(base.name, str):
            name = base.name
            if name == "_SERVER":
                key = dim.value if dim is not None and dim.kind == "String" else None
                if key and (key.startswith("HTTP_") or key in B.SERVER_KEYS):
                    kinds = SERVER_SRC_KINDS if key in B.SERVER_KEYS or key == "HTTP_HOST" else SRC_KINDS
                    if key in ("PHP_SELF", "PATH_INFO", "ORIG_PATH_INFO"):
                        kinds = kinds | {"xss"}         # /index.php/"><script> reaches PHP_SELF
                    return self.source("$_SERVER['%s']" % key, e, kinds)
                return EMPTY
            if name == "_SESSION" and dim is not None and dim.kind == "String":
                ss = self.e.stored_sources
                where = ss.get(("session", dim.value)) if ss else None
                if where is not None:
                    return self.source("stored session '%s' (written from request data at %s:%d)"
                                       % (dim.value, where[0], where[1]), e)
                return EMPTY
            if name == "GLOBALS" and dim is not None and dim.kind == "String":
                self.e.deps_globals.setdefault(dim.value, set()).add(self.rec.key)
                self.e._global_names.add(dim.value)
                return self.e.globals.get(dim.value, EMPTY)
            if name in B.SUPERGLOBALS:
                label = "$%s[%s]" % (name, repr(dim.value) if dim is not None and dim.kind == "String" else "...")
                return self.source(label, e)
            kk = self.key(e)
            if kk and kk in env:
                return env[kk]
            if kk and name in self.closed_arrays:
                return EMPTY
            whole = env.get(name, EMPTY)
            if dim is not None and dim.kind in ("String", "Int"):
                return t_project(whole, dim.value)
            return whole
        # chained: $_GET['a']['b'], $row['x']['y'], $this->data['k']
        t = self.expr(base, env, tenv)
        return t

    def prop_fetch(self, e, env, tenv):
        obj = e.obj
        name = e.name if isinstance(e.name, str) else None
        if obj.kind == "Var" and obj.name == "this" and name:
            local = env.get("this->" + name)
            stored = self.e.read_prop(self.cls, name, self.rec.key)
            if local is not None:
                # written earlier in this function: on this path the property
                # holds what was written here, not every value ever stored
                if self._prop_written.get(name):
                    return local
                return t_union(local, stored)
            return stored
        if name is None:
            return self.expr(obj, env, tenv)
        t = self.expr(obj, env, tenv)
        return t

    # ------------------------------------------------------------ sources
    def source(self, desc, node, kinds=SRC_KINDS):
        oid = self.e.new_origin(desc, self.fi, node)
        return {oid: kinds}

    def is_request(self, obj, tenv):
        """Is `obj` a Laravel / Symfony / WordPress request object?"""
        types = {t.lower() for t in self.types.infer(obj, tenv)}
        for t in types:
            if t in LV.REQUEST_CLASSES or t == WP.REST_REQUEST_CLASS:
                return True
            for c in self.p.ancestors(t):
                if c.fq.lower() in LV.REQUEST_CLASSES or c.fq.lower() == WP.REST_REQUEST_CLASS:
                    return True
                if c.parent and c.parent.lower() in LV.REQUEST_CLASSES:
                    return True
        if not types and obj.kind == "Var" and isinstance(obj.name, str) and obj.name.lower() in (
                "request", "req", "input", "wp_request", "rest_request"):
            return True
        if obj.kind == "Call" and obj.func.kind == "Name" and _lname(obj.func.name) == "request" and not obj.args:
            return True
        return False

    # -------------------------------------------------------------- sinks
    def sink(self, t, kind, rule, node, what, steps=()):
        if not t:
            return
        for o, kinds in t.items():
            if kind not in kinds:
                continue
            if isinstance(o, int):
                st = steps + (("sink: " + what, self.fi.rel, node.line, node.col),) if not steps else steps
                self.e.report(rule, o, self.fi, node, st, what)
            else:
                st = steps + (("sink: " + what, self.fi.rel, node.line, node.col),) if not steps else steps
                key = (_pidx(o), rule, kind, st[-1][1], st[-1][2])
                if key not in self.summary.sinks:
                    self.summary.sinks[key] = st

    def _args(self, args, env, tenv):
        out = []
        for a in args or []:
            out.append(self.expr(a.value, env, tenv) if a is not None else EMPTY)
        return out

    def _spec_args(self, spec, n):
        idx = spec.get("args", [0])
        if idx == "*":
            return list(range(n))
        out = []
        for i in idx:
            j = i if i >= 0 else n + i
            if 0 <= j < n:
                out.append(j)
        return out

    def check_fn_sinks(self, name, call, ats):
        if name == "unserialize" and len(call.args) > 1 and _no_classes(call.args[1].value):
            return
        if name == "curl_setopt" and len(call.args) >= 3 and len(ats) >= 3 and \
                call.args[1].value.kind == "Name" and _lname(call.args[1].value.name) == "curlopt_url":
            self.sink(ats[2], "url", "ssrf-curl", call, "curl_setopt(CURLOPT_URL)")
        for spec in _FN_SINKS.get(name, ()):
            sargs = spec.get("args")
            if isinstance(sargs, dict):
                spec = dict(spec, args=sargs.get(name, spec.get("default_args", [0])))
            if name in _CALLBACK_LAST:
                spec = dict(spec, args=[_CALLBACK_LAST[name]])
            for i in self._spec_args(spec, len(ats)):
                t = ats[i]
                if not t:
                    continue
                if spec["taint"] == "path" and spec.get("ssrf_rule"):
                    self.sink(t, "path", spec["rule"], call, name + "()")
                    continue
                self.sink(t, spec["taint"], spec["rule"], call, name + "()")

    # --------------------------------------------------------------- calls
    def call(self, c, env, tenv):
        fn = c.func
        if fn.kind != "Name":
            ats = self._args(c.args, env, tenv)
            if fn.kind == "Var" and isinstance(fn.name, str):
                ft = env.get(fn.name, EMPTY)
                self.sink(ft, "code", B.VARFUNC_RULE, c, "$%s()" % fn.name)
                return EMPTY
            if fn.kind in ("Closure", "ArrowFn"):
                key = self.p.function_key_for_node(fn)
                return self.apply_summary(key, ats, c, "closure", None)
            self.expr(fn, env, tenv)
            return EMPTY
        name = _lname(fn.name)
        if c.get("callable"):
            return EMPTY
        ats = self._args(c.args, env, tenv)
        short = name.rsplit("\\", 1)[-1]
        st = self._stored_read(short, c)
        if st is not None:
            return st
        sym = None if short in _MODELED_FNS else self.p.resolve_function(fn.name, self.ctx)
        if sym is not None and sym.key in self.e.units:
            ret = self.apply_summary(sym.key, ats, c, sym.name + "()", None, args_nodes=c.args, callee_params=sym.node.params)
            self.check_fn_sinks(name, c, ats)
            return ret
        self.check_fn_sinks(short, c, ats)
        self._fn_models(short, c, ats, env, tenv)
        return self.builtin(short, c, ats, env, tenv)

    def _stored_read(self, name, c):
        ss = self.e.stored_sources
        if not ss or name not in WP.STORED_READS:
            return None
        i = WP.STORED_READS[name]
        if len(c.args) <= i or c.args[i].value is None or c.args[i].value.kind != "String":
            return None
        store = "option" if i == 0 else "meta"
        where = ss.get((store, c.args[i].value.value))
        if where is None:
            return None
        return self.source("stored %s '%s' (written from request data at %s:%d)"
                           % (store, c.args[i].value.value, where[0], where[1]), c)

    def _fn_models(self, name, c, ats, env, tenv):
        """Framework helper functions: sinks, hooks, templates, authz bookkeeping."""
        if name == "header" and c.args:
            a = c.args[0].value
            parts = []
            if a.kind == "BinOp" and a.op == ".":
                self._flatten(a, parts)
            elif a.kind == "Interp":
                parts = list(a.parts)
            if parts and parts[0].kind == "String" and B.is_location_literal(parts[0].value):
                rest = self.concat(parts[1:], env, tenv)
                self.sink(rest, "redirect", B.HEADER_REDIRECT_RULE, c, "header('Location: ...')")
        for fname, idx, kind, rule in LV.FUNC_SINKS:
            if name == fname and len(ats) > idx[0]:
                if name == "response" and len(ats) > 2:
                    continue
                self.sink(ats[idx[0]], kind, rule, c, name + "()")
        if name in WP.OPTION_KEY_SINKS:
            i = WP.OPTION_KEY_SINKS[name]
            if len(ats) > i:
                self.sink(ats[i], "env", "wp-option-key-tainted", c, name + "()")
            # request data stored under a fixed option / meta key: reading that
            # key later is a (second-order) source
            if len(c.args) > i + 1 and c.args[i].value is not None and c.args[i].value.kind == "String" \
                    and len(ats) > i + 1 and any(isinstance(o, int) for o in ats[i + 1]):
                store = "option" if i == 0 else "meta"
                self.e.stored.setdefault((store, c.args[i].value.value), (self.fi.rel, c.line))
        if name in WP.WP_WRITES:
            self.summary.writes.append((name + "()", self.fi.rel, c.line))
        if name in WP.WP_GUARDS:
            self.summary.guards = True
            if name in WP.WP_NONCES:
                self.summary.nonce = True
        if name in WP.HOOK_FUNCS and len(c.args) >= 2:
            hook = c.args[0].value
            if hook.kind == "String" and hook.value.startswith("wp_ajax_"):
                typ = "nopriv" if hook.value.startswith("wp_ajax_nopriv_") else "priv"
                keys = self._callable_keys(c.args[1].value, tenv)
                self.e.ajax_hooks.append((typ, keys, self.fi, c, hook.value))
            elif hook.kind == "String" and hook.value.startswith("admin_post_"):
                typ = "nopriv" if hook.value.startswith("admin_post_nopriv_") else "adminpost"
                keys = self._callable_keys(c.args[1].value, tenv)
                self.e.ajax_hooks.append((typ, keys, self.fi, c, hook.value))
        if name == "register_rest_route" and len(c.args) >= 3:
            self._rest_route(c.args[2].value, c, tenv)
        if name == "view" and c.args:
            self._bind_view("blade", c.args[0].value, c.args[1].value if len(c.args) > 1 else None, c, env, tenv)
        if name == "compact":
            pass

    def _rest_route(self, arr, c, tenv):
        if arr is None or arr.kind != "Array":
            return
        routes = [arr]
        if all(it is not None and it.key is None and it.value is not None and it.value.kind == "Array"
               for it in arr.items) and arr.items:
            routes = [it.value for it in arr.items]
        for r in routes:
            cb, perm = None, None
            for it in r.items:
                if it is None or it.key is None or it.key.kind != "String":
                    continue
                if it.key.value == "callback":
                    cb = it.value
                elif it.key.value == "permission_callback":
                    perm = it.value
            if cb is None:
                continue
            if perm is not None and perm.kind == "String" and perm.value.lstrip("\\") == "__return_true":
                keys = self._callable_keys(cb, tenv)
                if keys:
                    self.e.rest_open.append((keys, self.fi, c))

    def _callable_keys(self, e, tenv):
        cg = self.p.callgraph
        if cg is None or e is None:
            return []
        from .callgraph import _Unit
        u = _Unit.__new__(_Unit)
        u.cg, u.p, u.rec, u.fi, u.ctx, u.cls = cg, self.p, self.rec, self.fi, self.ctx, self.cls
        u.types, u.strs, u.top = {k: list(v) for k, v in tenv.items() if not k.startswith("[]")}, {}, set()
        try:
            return [k for k in u.callable_targets(e) if k in self.e.units]
        except Exception:  # noqa: BLE001
            return []

    def _bind_view(self, engine, name_node, data_node, c, env, tenv):
        if name_node is None or name_node.kind != "String":
            return
        binds = self._template_data(data_node, env, tenv)
        self.e.bind_template(engine, name_node.value, binds, self.fi, c)

    def _template_data(self, data, env, tenv):
        binds = {}
        if data is None:
            return binds
        if data.kind == "Array":
            for it in data.items:
                if it is None or it.key is None or it.key.kind != "String":
                    continue
                binds[it.key.value] = self.expr(it.value, env, tenv)
        elif data.kind == "Call" and data.func.kind == "Name" and _lname(data.func.name) == "compact":
            for a in data.args:
                if a.value.kind == "String":
                    binds[a.value.value] = env.get(a.value.value, EMPTY)
        return binds

    def builtin(self, name, c, ats, env, tenv):
        if name in B.SQL_ESCAPERS:
            t = (ats[-1] if name.startswith("mysqli_") or name.startswith("pg_") else ats[0]) if ats else EMPTY
            out = {}
            for o, v in t.items():
                nv = (v - {"sql", "mass"}) | ({"sqlq"} if "sql" in v else frozenset())
                out[o] = frozenset(nv)
            return out
        if name in WP.SOURCE_FUNCS:
            return self.source(name + "()", c)
        if name == "file_get_contents" and c.args and c.args[0].value.kind == "String" and \
                c.args[0].value.value.startswith("php://input"):
            return self.source("php://input", c)
        if name == "request":
            if c.args:
                return self.source("request(%s)" % _arg_label(c.args[0].value), c)
            return EMPTY
        if name in ("filter_input", "filter_input_array"):
            if len(c.args) >= 3 and c.args[2].value.kind == "Name":
                flt = c.args[2].value.name.lstrip("\\")
                if B.FILTER_SAFE.match(flt):
                    return EMPTY
                if B.FILTER_XSS.match(flt):
                    return t_remove(self.source(name + "()", c), {"xss"})
            return self.source(name + "()", c)
        san = B.SANITIZERS.get(name, False)
        if san is not False:
            if san is B.CLEAR_ALL:
                return EMPTY
            t = ats[0] if ats else EMPTY
            if san is None:          # filter_var
                if len(c.args) >= 2 and c.args[1].value.kind == "Name":
                    flt = c.args[1].value.name.lstrip("\\")
                    if B.FILTER_SAFE.match(flt):
                        return EMPTY
                    if B.FILTER_XSS.match(flt):
                        return t_remove(t, {"xss", "mass"})
                return t_remove(t, {"mass"})
            if name in ("urlencode", "rawurlencode", "http_build_query"):
                san = san | {"url"}
            return t_remove(t, san | {"mass"})
        if name in _PATH_HELPERS:
            out = EMPTY
            for t in ats:
                out = t_union(out, t)
            return t_remove(out, {"mass"})
        if name in ("sprintf", "vsprintf") and c.args and c.args[0].value.kind == "String" and name == "sprintf":
            fmt = c.args[0].value.value or ""
            out = EMPTY
            fixed = False
            pieces = re.split(r"(%(?:\d+\$)?[-+ 0'#]*\d*(?:\.\d+)?[bcdeEfFgGosuxX%])", fmt)
            ai = 1
            for piece in pieces:
                if not piece:
                    continue
                if piece.startswith("%") and piece != "%%":
                    t = ats[ai] if ai < len(ats) else EMPTY
                    ai += 1
                    if fixed:
                        t = t_remove(t, {"url"})
                    elif not t:
                        fixed = True
                    out = t_union(out, t)
                elif "/" in piece or "?" in piece or "." in piece:
                    fixed = True
            return t_remove(out, {"mass"})
        if name == "preg_replace" and len(c.args) >= 3 and c.args[0].value.kind == "String" \
                and B.negclass_pattern(c.args[0].value.value or "") and c.args[1].value.kind == "String" \
                and re.fullmatch(r"[A-Za-z0-9_\-]*", c.args[1].value.value or ""):
            return EMPTY       # everything outside a safe character class was removed
        if name == "pathinfo" and len(c.args) >= 2 and c.args[1].value.kind == "Name" \
                and _lname(c.args[1].value.name) == "pathinfo_extension":
            # the part after the last dot cannot contain "/" or ".." to lead a path
            return t_remove(ats[0] if ats else EMPTY, {"path", "incl", "mass"})
        if name in B.PROPAGATORS:
            out = EMPTY
            for i, t in enumerate(ats):
                if name in ("str_replace", "str_ireplace", "preg_replace") and i == 0:
                    continue
                if name == "implode" and len(ats) > 1 and i == 0:
                    continue
                out = t_union(out, t)
            if name not in B.MASS_KEEPERS:
                out = t_remove(out, {"mass"})
            return out
        if name in B.STATEMENT_GUARDS:
            idx = B.STATEMENT_GUARDS[name]
            if len(c.args) > idx:
                for v in self.vars_in(c.args[idx].value):
                    env[v] = EMPTY
            if name in WP.WP_GUARDS:
                self.summary.guards = True
                if name in WP.WP_NONCES:
                    self.summary.nonce = True
            return EMPTY
        if name in ("array_map",) and len(ats) > 1:
            cb = c.args[0].value
            if cb.kind == "String" and cb.value.lower() not in B.SANITIZERS:
                sym = self.p.resolve_function(cb.value, self.ctx)
                if sym is not None and sym.key in self.e.units:
                    return t_remove(self.apply_summary(sym.key, [ats[1]], c, cb.value + "()", None), {"mass"})
            if cb.kind == "String" and B.SANITIZERS.get(cb.value.lower(), False) is B.CLEAR_ALL:
                return EMPTY
            if cb.kind == "String" and isinstance(B.SANITIZERS.get(cb.value.lower(), False), frozenset):
                return t_remove(ats[1], B.SANITIZERS[cb.value.lower()] | {"mass"})
            return t_remove(ats[1], {"mass"})
        return EMPTY

    # ------------------------------------------------------- summaries
    def apply_summary(self, key, ats, call, label, recv, args_nodes=None, callee_params=None, this_call=False):
        if not key or key not in self.e.units:
            return EMPTY
        s = self.e.summaries.get(key)
        if s is None:
            return EMPTY
        # named arguments
        if args_nodes and callee_params and any(a is not None and a.name for a in args_nodes):
            pos = {p.name: i for i, p in enumerate(callee_params)}
            fixed = [EMPTY] * max(len(callee_params), len(ats))
            j = 0
            for a, t in zip(args_nodes, ats):
                if a.name and a.name in pos:
                    fixed[pos[a.name]] = t
                else:
                    if j < len(fixed):
                        fixed[j] = t
                    j += 1
            ats = fixed
        crec = self.e.units.get(key)
        where = ""
        if crec is not None and crec.node is not None and crec.kind in ("function", "method"):
            where = " (%s:%d)" % (crec.file.rel, crec.node.line)
        hop = ("call %s%s" % (label, where), self.fi.rel, call.line, call.col)
        named = bool(args_nodes) and any(a is not None and a.name for a in args_nodes)

        def arg_t(pi):
            if isinstance(pi, int):
                return ats[pi] if pi < len(ats) else EMPTY
            i, key = pi
            if i >= len(ats) or not ats[i]:
                return EMPTY
            if args_nodes and not named and i < len(args_nodes) and args_nodes[i] is not None:
                a = args_nodes[i].value
                env, tenv = self._env, self._tenv
                if a is not None and a.kind == "Array" and env is not None:
                    if all(it is not None and not it.unpack and it.key is not None
                           and it.key.kind in ("String", "Int") for it in a.items):
                        for it in a.items:
                            if str(it.key.value) == str(key):
                                return self.expr_quiet(it.value, env, tenv)
                        return EMPTY
                elif a is not None and a.kind == "Var" and isinstance(a.name, str) and env is not None:
                    kk = "%s[%s]" % (a.name, key)
                    if kk in env:
                        return env[kk]
                    if a.name in self.closed_arrays:
                        return EMPTY
            return t_project(ats[i], key)

        ret = EMPTY
        for o, kinds in s.ret.items():
            if isinstance(o, int):
                if sum(1 for h in self.e.origins[o].hops if h[0].startswith("returned by")) >= MAX_RET_DEPTH:
                    continue
                ret = t_union(ret, {self.e.derive(o, ("returned by " + label, self.fi.rel, call.line, call.col)): kinds})
            else:
                at = arg_t(_pidx(o))
                if at:
                    ret = t_union(ret, t_keep(at, kinds))
        for (pi, rule, kind, _f, _l), steps in s.sinks.items():
            at = arg_t(pi)
            if not at:
                continue
            # Deep chains through library code are where unmodelled validation
            # hides (validate_plugin(), a whitelist three calls down); keep
            # parameter-to-sink flows to MAX_CALL_DEPTH calls.
            if sum(1 for h in steps if h[0].startswith("call ")) + 1 > _RULE_DEPTH.get(rule, MAX_CALL_DEPTH):
                continue
            self.sink(at, kind, rule, call, label, steps=(hop,) + steps)
        for prop, d in s.propw.items():
            for o, kinds in d.items():
                if isinstance(o, int):
                    continue
                at = arg_t(_pidx(o))
                if at:
                    t = t_keep(at, kinds)
                    if this_call:
                        cur = self.summary.propw.get(prop, EMPTY)
                        sym = {k: v for k, v in t.items() if not isinstance(k, int)}
                        if sym:
                            self.summary.propw[prop] = t_union(cur, sym)
                    # Request data a caller hands to a constructor or setter is
                    # stored per class only for calls on $this: a shared class
                    # store fed from outside would taint every instance (every
                    # Collection in the program once one holds request data).
                    callee = self.e.units.get(key)
                    if this_call and callee is not None and callee.cls:
                        self.e.add_prop(callee.cls, prop, t)
        if s.writes:
            self.summary.writes.extend(s.writes[:2])
        return ret

    def method_call(self, c, env, tenv):
        obj = c.obj
        name = c.name if isinstance(c.name, str) else None
        recv_t = self.expr(obj, env, tenv)
        ats = self._args(c.args, env, tenv)
        if name is None or c.get("callable"):
            return EMPTY
        lname = name.lower()
        # --- request sources
        if obj.kind == "PropFetch" and isinstance(obj.name, str) and obj.name.lower() in SF.BAG_NAMES \
                and self.is_request(obj.obj, tenv):
            if lname in SF.BAG_SAFE_METHODS:
                return EMPTY
            kinds = SRC_KINDS | ({"mass"} if lname == "all" else frozenset())
            return self.source("$request->%s->%s(%s)" % (obj.name, name, _arg_label(c.args[0].value) if c.args else ""),
                               c, kinds)
        if self.is_request(obj, tenv):
            if lname in LV.REQUEST_SAFE_METHODS:
                return EMPTY
            if lname in ("validated", "safe"):
                return self._validated(obj, c, tenv)
            whole = LV.REQUEST_METHODS.get(lname)
            if whole is not None or lname in SF.REQUEST_SOURCE_METHODS or lname in WP.REST_SOURCE_METHODS:
                kinds = SRC_KINDS
                if whole == "yes" or (whole == "maybe" and not c.args):
                    kinds = kinds | {"mass"}
                # the request's own URL (trusted host + path): not a request-forgery target
                if lname in SF.SELF_URL_METHODS or lname in ("url", "fullurl", "root", "path"):
                    kinds = kinds - {"url"}
                return self.source("$request->%s(%s)" % (name, _arg_label(c.args[0].value) if c.args else ""),
                                   c, kinds)
        if lname in B.SAFE_RETURN_METHODS and not c.args:
            return EMPTY
        if lname in _ORM_WRITE_METHODS:
            self.summary.ormw.append(("->%s()" % name, self.fi.rel, c.line))
        # --- sanitizing methods ($wpdb->prepare, $pdo->quote, ->escape_string)
        recv_name = _recv_name(obj)
        recv_types = {t.lower() for t in self.types.infer(obj, tenv)}
        self._method_sinks(lname, c, ats, recv_name, recv_types, obj, env, tenv)
        if lname in _SANITIZING_METHODS:
            if lname in B.SQL_ESCAPE_METHODS and ats:
                return {o: frozenset((v - {"sql", "mass"}) | ({"sqlq"} if "sql" in v else frozenset()))
                        for o, v in ats[0].items()}
            return EMPTY
        # --- project methods
        ms = self.types.methods_for(obj, name, tenv)
        keys = [m.key for m in ms if m.key in self.e.units]
        if not keys:
            # untyped receiver: follow the name only when it is (nearly) unique
            keys = self._edge_targets(c, lname)
            if len(keys) > 2:
                keys = []
        if keys:
            ret = EMPTY
            this_call = obj.kind == "Var" and obj.name == "this"
            for k in keys[:6]:
                callee = self.e.units[k]
                ret = t_union(ret, self.apply_summary(k, ats, c, self._callee_label(callee), obj,
                                                      args_nodes=c.args, callee_params=callee.params,
                                                      this_call=this_call))
            return ret
        # --- framework fluent objects
        if lname in ("with",) and obj.kind == "Call" and obj.func.kind == "Name" and _lname(obj.func.name) == "view":
            if obj.args and obj.args[0].value.kind == "String":
                if len(c.args) >= 2 and c.args[0].value.kind == "String":
                    self.e.bind_template("blade", obj.args[0].value.value, {c.args[0].value.value: ats[1]}, self.fi, c)
                elif c.args:
                    self.e.bind_template("blade", obj.args[0].value.value,
                                         self._template_data(c.args[0].value, env, tenv), self.fi, c)
            return EMPTY
        if lname in ("render", "renderview", "display") and c.args and c.args[0].value.kind == "String" \
                and c.args[0].value.value.endswith(".twig"):
            data = c.args[1].value if len(c.args) > 1 else None
            self.e.bind_template("twig", c.args[0].value.value, self._template_data(data, env, tenv), self.fi, c)
            return EMPTY
        # unknown method on a tainted value: a fluent string/collection wrapper keeps it
        if recv_t and lname in _FLUENT_KEEP:
            return t_remove(recv_t, {"mass"})
        return EMPTY

    def _callee_label(self, rec):
        if rec.kind == "method":
            return "%s::%s()" % ((rec.cls or "?").rsplit("\\", 1)[-1], rec.name)
        if rec.kind == "function":
            return "%s()" % rec.name
        return rec.key

    def _edge_targets(self, c, lname):
        cg = self.p.callgraph
        if cg is None:
            return []
        out = []
        for e in cg.out.get(self.rec.key, ()):
            if e.line == c.line and e.kind in ("method-name", "method", "method-impl") and \
                    e.callee.rsplit("::", 1)[-1] == lname and e.callee in self.e.units:
                if e.callee not in out:
                    out.append(e.callee)
        return out

    def _validated(self, obj, c, tenv):
        """FormRequest::validated(): safe for keys whose rules leave no room for a
        payload; the rest stays tainted."""
        types = self.types.infer(obj, tenv)
        rules = None
        for t in types:
            m = self.p.method_lookup(t, "rules")
            if m is not None and m.node is not None and m.node.body:
                rules = _literal_rules(m.node.body)
                if rules is not None:
                    break
        key = c.args[0].value.value if c.args and c.args[0].value.kind == "String" else None
        if rules is not None:
            if key is not None:
                r = rules.get(key)
                if r is not None and _restrictive(r):
                    return EMPTY
            elif rules and all(_restrictive(r) for r in rules.values()):
                return EMPTY
        return self.source("$request->validated(%s)" % (repr(key) if key else ""), c, SRC_KINDS)

    def _method_sinks(self, lname, c, ats, recv_name, recv_types, obj, env, tenv):
        for spec in _METHOD_SINKS.get(lname, ()):
            rx = spec.get("_rx")
            classes = spec.get("classes")
            ok = False
            if classes:
                ok = any(t in classes or any(a.fq.lower() in classes for a in self.p.ancestors(t))
                         for t in recv_types)
            if not ok and rx is not None:
                ok = bool(recv_name and rx.search(recv_name))
            if not ok and rx is None and not classes:
                # Doctrine method names are generic (executeQuery, fetchOne):
                # require a Doctrine receiver by type or by name
                ok = spec["rule"] != "sql-doctrine" or bool(recv_name and _DOCTRINE_RECV.search(recv_name))
            if ok and spec["rule"] == "sql-db-query" and recv_name.lower() == "wpdb":
                ok = False           # reported as sql-wpdb
            if not ok:
                continue
            for i in self._spec_args(spec, len(ats)):
                self.sink(ats[i], spec["taint"], spec["rule"], c, "->%s()" % lname)
        if lname in WP.WPDB_WRITES and recv_name and recv_name.lower() == "wpdb" \
                and not (lname == "query" and c.args and _readonly_sql(c.args[0].value)):
            self.summary.writes.append(("$wpdb->%s()" % lname, self.fi.rel, c.line))
        # Doctrine via types
        if lname in SF.DOCTRINE_SINKS and ats and recv_types and any(
                t in SF.DOCTRINE_CLASSES or any(a.fq.lower() in SF.DOCTRINE_CLASSES for a in self.p.ancestors(t))
                for t in recv_types):
            self.sink(ats[0], "sql", "sql-doctrine", c, "->%s()" % lname)
        # HTTP clients (Guzzle, Symfony HttpClient, PSR-18)
        if recv_types and any(t in SF.HTTP_CLIENT_CLASSES or
                              any(a.fq.lower() in SF.HTTP_CLIENT_CLASSES for a in self.p.ancestors(t))
                              for t in recv_types):
            if lname in ("request", "requestasync") and len(ats) >= 2:
                self.sink(ats[1], "url", "ssrf-http-client", c, "->%s()" % lname)
            elif lname in ("get", "post", "put", "patch", "delete", "head", "getasync", "postasync") and ats:
                self.sink(ats[0], "url", "ssrf-http-client", c, "->%s()" % lname)
        # Laravel chains: redirect()->away($u), response()->download($p), Http::withHeaders()->get($u)
        root = _chain_root(obj)
        if root is not None:
            for chain_name, specs in LV.CHAIN_SINKS.items():
                if root == chain_name:
                    for names, idx, kind, rule in specs:
                        if lname in names and len(ats) > idx[0]:
                            self.sink(ats[idx[0]], kind, rule, c, "%s()->%s()" % (chain_name, lname))
        # mass assignment on a model instance
        if lname in LV.MASS_METHODS and ats:
            for t in recv_types:
                if self._mass_assignable(t, lname):
                    self.sink(ats[0], "mass", "mass-assignment", c, "->%s()" % lname)
                    break
        if lname in WP.REDIRECT_SAFE:
            return

    def _mass_assignable(self, cls, method):
        if not self._is_model(cls):
            return False
        if method in LV.FORCE_METHODS:
            return True
        for c in self.p.ancestors(cls):
            ps = c.props.get("guarded")
            if ps is not None and ps.node is not None:
                d = ps.node.get("default")
                return d is not None and d.kind == "Array" and not d.items
            fl = c.props.get("fillable")
            if fl is not None:
                return False
        return False

    def _is_model(self, cls):
        for c in self.p.ancestors(cls):
            if c.parent and c.parent.lower() == LV.MODEL_BASE:
                return True
            if c.fq.lower() == LV.MODEL_BASE:
                return True
        return False

    def static_call(self, c, env, tenv):
        name = c.name if isinstance(c.name, str) else None
        ats = self._args(c.args, env, tenv)
        if name is None or c.cls.kind != "Name" or c.get("callable"):
            if c.cls.kind != "Name":
                self.expr(c.cls, env, tenv)
            return EMPTY
        lname = name.lower()
        written = c.cls.name
        low = _lname(written)
        fq = self.p.resolve_class(written, self.ctx)
        if low == "parent" and self.cls:
            cs = self.p.get_class(self.cls)
            fq = cs.parent if cs is not None and cs.parent else fq
        short = _short(fq) if low not in ("self", "static", "parent") else low
        if lname in _ORM_STATIC_WRITES and short.lower() not in ("route", "gate", "auth", "cache", "session",
                                                                 "log", "event", "config", "storage", "mail"):
            self.summary.ormw.append(("%s::%s()" % (short, name), self.fi.rel, c.line))
        # facade sources: Request::input('x'), Input::get('x')
        if short in ("request", "input") and (lname in LV.REQUEST_METHODS) and low not in ("self", "static"):
            kinds = SRC_KINDS | ({"mass"} if LV.REQUEST_METHODS.get(lname) == "yes" or
                                 (LV.REQUEST_METHODS.get(lname) == "maybe" and not c.args) else frozenset())
            return self.source("%s::%s()" % (written, name), c, kinds)
        # TAINT_SINKS static specs ("static": ["db"], "names": [...])
        for spec in _STATIC_SINKS.get(short, ()):
            if lname in spec["names"]:
                for i in self._spec_args(spec, len(ats)):
                    self.sink(ats[i], spec["taint"], spec["rule"], c, "%s::%s()" % (written, name))
        for fac, names, idx, kind, rule in LV.STATIC_SINKS:
            if short == fac and lname in names and len(ats) > idx[0]:
                self.sink(ats[idx[0]], kind, rule, c, "%s::%s()" % (written, name))
        # Symfony Process::fromShellCommandline($cmd)
        if lname == "fromshellcommandline" and short == "process" and ats:
            self.sink(ats[0], "cmd", "cmd-process", c, "Process::fromShellCommandline()")
        # mass assignment: Model::create($request->all())
        if lname in LV.MASS_METHODS_STATIC and ats:
            idx = 1 if lname in ("updateorcreate", "firstorcreate", "firstornew") and len(ats) > 1 else 0
            if self._mass_assignable(fq, lname if lname in LV.FORCE_METHODS else "create"):
                self.sink(ats[idx], "mass", "mass-assignment", c, "%s::%s()" % (written, name))
        if short == "view" and lname == "make" and c.args:
            self._bind_view("blade", c.args[0].value, c.args[1].value if len(c.args) > 1 else None, c, env, tenv)
        m = self.p.method_lookup(fq, name) if fq else None
        if m is not None and m.key in self.e.units:
            callee = self.e.units[m.key]
            this_call = low in ("self", "static", "parent") and not m.static
            return self.apply_summary(m.key, ats, c, self._callee_label(callee), None, args_nodes=c.args,
                                      callee_params=callee.params, this_call=this_call)
        return EMPTY

    def new(self, n, env, tenv):
        ats = self._args(n.args, env, tenv)
        cls_node = n.cls
        if cls_node.kind != "Name":
            if cls_node.kind not in ("Class",):
                self.expr(cls_node, env, tenv)
            return EMPTY
        fq = self.p.resolve_class(cls_node.name, self.ctx)
        low = fq.lower()
        anc = {a.fq.lower() for a in self.p.ancestors(fq)} | {low}
        if (low == SF.PROCESS_CLASS or _short(fq) == "process") and ats and n.args and \
                n.args[0].value.kind != "Array":
            self.sink(ats[0], "cmd", "cmd-process", n, "new Process(string)")
        if anc & set(SF.RESPONSE_CLASSES) and not anc & set(SF.SAFE_RESPONSE_CLASSES) and ats:
            hdr = n.args[2].value if len(n.args) > 2 else None
            if not _non_html_headers(hdr):
                self.sink(ats[0], "xss", "xss-response", n, "new Response()")
        if self._is_model(fq) and ats and self._mass_assignable(fq, "create"):
            self.sink(ats[0], "mass", "mass-assignment", n, "new %s()" % _short(fq))
        m = self.p.method_lookup(fq, "__construct")
        if m is not None and m.key in self.e.units:
            callee = self.e.units[m.key]
            self.apply_summary(m.key, ats, n, "new %s()" % fq.rsplit("\\", 1)[-1], None,
                               args_nodes=n.args, callee_params=callee.params)
        return EMPTY


# --------------------------------------------------------------------- helpers
def _no_classes(e):
    if e is None or e.kind != "Array":
        return False
    for it in e.items:
        if it is not None and it.key is not None and it.key.kind == "String" and it.key.value == "allowed_classes":
            v = it.value
            return v is not None and ((v.kind == "Name" and _lname(v.name) == "false") or v.kind == "Array")
    return False


def _has_authz(node):
    stack = [node]
    while stack:
        x = stack.pop()
        if x is None:
            continue
        if isinstance(x, list):
            stack.extend(x)
            continue
        k = getattr(x, "kind", None)
        if k is None:
            continue
        if k == "Attribute":
            if str(getattr(x, "name", "")).lower().rsplit("\\", 1)[-1] in _AUTHZ_ATTRS:
                return True
        elif k == "Call" and getattr(x.func, "kind", "") == "Name":
            if _lname(x.func.name).rsplit("\\", 1)[-1] in _AUTHZ_FUNCS:
                return True
        elif k in ("MethodCall", "NullsafeMethodCall") and isinstance(x.name, str):
            n = x.name.lower()
            if n in _AUTHZ_METHODS:
                return True
            if n == "middleware" and x.args:
                v = x.args[0].value
                vals = [v] if v is not None and v.kind == "String" else \
                    [it.value for it in (v.items if v is not None and v.kind == "Array" else []) if it is not None]
                if any(getattr(vv, "kind", "") == "String" and _AUTHZ_MIDDLEWARE.match(vv.value or "") for vv in vals):
                    return True
        elif k == "StaticCall" and getattr(x.cls, "kind", "") == "Name" and isinstance(x.name, str):
            if (_lname(x.cls.name).rsplit("\\", 1)[-1], x.name.lower()) in _AUTHZ_STATIC:
                return True
        if k in ("Function", "Class", "Closure", "ArrowFn") and x is not node:
            continue
        for g in (x.get("attrs") or []) if hasattr(x, "get") else []:
            stack.append(g)
        stack.extend(x.children())
    return False


def _readonly_sql(e):
    """A query whose text starts with SELECT/SHOW/DESCRIBE/EXPLAIN changes nothing."""
    first = e
    while first is not None and first.kind == "BinOp" and first.op == ".":
        first = first.left
    if first is None:
        return False
    if first.kind == "String":
        txt = first.value or ""
    elif first.kind == "Interp":
        txt = next((p.value or "" for p in first.parts if p is not None and p.kind == "String"), "")
        if first.parts and first.parts[0] is not None and first.parts[0].kind != "String":
            return False
    else:
        return False
    return bool(re.match(r"\s*(select|show|describe|desc|explain)\b", txt, re.I))


def _squash(trace):
    """Drop repeated 'assigned to $x' steps (a value rebuilt line by line)."""
    out = []
    for h in trace:
        if out and h["note"] == out[-1]["note"] and h["note"].startswith("assigned to") and h["file"] == out[-1]["file"]:
            out[-1] = h
        else:
            out.append(h)
    return out


def _unescaped_quotes(s):
    out = []
    esc = False
    for ch in s:
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch in ("'", '"', "`"):
            out.append(ch)
    return out


def _arg_label(e):
    if e is None:
        return ""
    if e.kind == "String":
        return repr(e.value)[:40]
    return "..."


def _recv_name(obj):
    if obj.kind == "Var" and isinstance(obj.name, str):
        return obj.name
    if obj.kind == "PropFetch" and isinstance(obj.name, str):
        return obj.name
    if obj.kind == "StaticProp" and isinstance(obj.name, str):
        return obj.name
    if obj.kind == "ArrayDim" and obj.dim is not None and obj.dim.kind == "String":
        return obj.dim.value
    return ""


def _chain_root(e):
    """'redirect' for redirect()->x()->y; 'http' for Http::withHeaders()->...; else None."""
    x = e
    for _ in range(12):
        if x is None:
            return None
        if x.kind == "MethodCall":
            x = x.obj
            continue
        if x.kind == "Call" and x.func.kind == "Name":
            return _short(x.func.name)
        if x.kind == "StaticCall" and x.cls.kind == "Name":
            return _short(x.cls.name)
        return None
    return None


def _non_html_headers(h):
    if h is None or h.kind != "Array":
        return False
    for it in h.items:
        if it is None or it.key is None or it.key.kind != "String":
            continue
        if it.key.value.lower() == "content-type" and it.value is not None and it.value.kind == "String":
            return "html" not in it.value.value.lower()
    return False


def _literal_rules(body):
    """{field: [rule tokens]} from `return [ 'f' => 'required|integer', ... ];`, else None."""
    for s in body:
        if s is not None and s.kind == "Return" and s.expr is not None and s.expr.kind == "Array":
            out = {}
            for it in s.expr.items:
                if it is None or it.key is None or it.key.kind != "String":
                    return None
                v = it.value
                toks = []
                if v.kind == "String":
                    toks = [x.strip() for x in v.value.split("|") if x.strip()]
                elif v.kind == "Array":
                    for x in v.items:
                        if x is None or x.value is None:
                            continue
                        if x.value.kind == "String":
                            toks.append(x.value.value.strip())
                        else:
                            toks.append("?")
                else:
                    return None
                out[it.key.value] = toks
            return out
    return None


def _restrictive(tokens):
    return any(LV.RESTRICTIVE.match(t) for t in tokens) and all(t != "?" for t in tokens)


# Sink tables indexed once
_FN_SINKS = {}
_METHOD_SINKS = {}
_STATIC_SINKS = {}
for _s in B.SINKS:
    if "fn" in _s:
        for _f in _s["fn"]:
            _FN_SINKS.setdefault(_f, []).append(_s)
    elif "method" in _s:
        _s = dict(_s)
        _s["_rx"] = re.compile(_s["receiver"]) if _s.get("receiver") else None
        for _m in _s["method"]:
            _METHOD_SINKS.setdefault(_m, []).append(_s)
    elif "static" in _s:
        for _c in _s["static"]:
            _STATIC_SINKS.setdefault(_c, []).append(_s)
for _names, _idx, _kind, _rule in LV.METHOD_SINKS:
    for _m in _names:
        _METHOD_SINKS.setdefault(_m, []).append({"rule": _rule, "args": list(_idx), "taint": _kind, "_rx": None})
for _m in WP.WPDB_READ_SINKS:
    pass
_DOCTRINE_RECV = re.compile(r"(?i)^(em|entitymanager|entity_manager|manager|conn|connection|dbal|qb|querybuilder|doctrine)$")
_CMP_WRAPPERS = frozenset({"strtolower", "strtoupper", "trim", "ltrim", "rtrim", "mb_strtolower",
                           "mb_strtoupper", "strval", "basename", "pathinfo"})
_CALLBACK_LAST = {"usort": 1, "uasort": 1, "uksort": 1, "array_walk": 1}  # callback position
_PATH_HELPERS = frozenset({"storage_path", "base_path", "public_path", "resource_path", "app_path",
                           "database_path", "config_path", "lang_path", "asset", "url", "trailingslashit",
                           "untrailingslashit", "path_join"})
# State-changing ORM / query-builder calls (Laravel Eloquent and DB, Doctrine).
_ORM_WRITE_METHODS = frozenset({"save", "update", "delete", "destroy", "forcedelete", "insert", "upsert",
                                "updateorcreate", "firstorcreate", "increment", "decrement", "attach", "detach",
                                "sync", "persist", "remove", "push", "restore", "truncate", "forcefill"})
_ORM_STATIC_WRITES = frozenset({"create", "destroy", "insert", "updateorcreate", "firstorcreate", "forcecreate",
                                "upsert", "update", "delete", "statement", "unprepared", "truncate"})
_MODELED_FNS = frozenset(set(B.SANITIZERS) | set(B.SQL_ESCAPERS) | set(B.PROPAGATORS) | set(B.STATEMENT_GUARDS)
                         | set(B.GUARD_FNS) | set(B.VALIDATORS) | set(WP.SOURCE_FUNCS) | {"wp_unslash", "absint"})
_SANITIZING_METHODS = {"prepare", "quote", "escape_string", "real_escape_string", "escape", "esc_like",
                       "getint", "getboolean", "getalnum", "getdigits", "getalpha"}
_FLUENT_KEEP = frozenset({"tostring", "trim", "lower", "upper", "value", "__tostring", "first", "last", "get",
                          "toarray", "all", "values", "implode", "join", "replace", "append", "prepend"})


def rule_meta(rule):
    return RULES_BY_ID.get(rule)
