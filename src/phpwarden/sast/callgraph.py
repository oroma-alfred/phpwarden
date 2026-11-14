"""Call graph and include resolution over a Project.

Edges (caller key -> callee key) are recorded for:
  call         plain function calls             foo()
  static       static / self / parent calls     Foo::bar(), parent::__construct()
  method       method calls with a known receiver type ($this, new X, typed
               params/properties/returns, @var/@param/@return docblocks)
  method-impl  the same, dispatched to subclasses/implementors of an interface
               or abstract receiver type
  method-name  method calls on an unknown receiver, resolved only when exactly
               one class in the project defines a method with that name
  new          constructor calls                new Foo()  -> Foo::__construct
  callback     callables handed to known invokers (call_user_func, array_map,
               usort, add_action, add_filter, preg_replace_callback, ...)
  route        framework routes (Laravel Route::get('/x', [Ctl::class, 'm']))
  include      include/require, including dynamic paths matched against files
"""
from __future__ import annotations

import os
import re

from .ast import Node
from .symbols import parse_doc, type_names

WILD = "\x00"

# function name -> index of the callable argument
_CALLBACK_ARG = {
    "call_user_func": 0, "call_user_func_array": 0, "forward_static_call": 0, "forward_static_call_array": 0,
    "array_map": 0, "array_filter": 1, "array_walk": 1, "array_walk_recursive": 1, "array_reduce": 1,
    "usort": 1, "uasort": 1, "uksort": 1, "register_shutdown_function": 0, "spl_autoload_register": 0,
    "preg_replace_callback": 1, "iterator_apply": 1, "set_error_handler": 0, "set_exception_handler": 0,
    "add_action": 1, "add_filter": 1, "add_shortcode": 1, "register_activation_hook": 1,
    "register_deactivation_hook": 1, "register_uninstall_hook": 1, "wp_ajax": 1,
}
_ROUTE_METHODS = frozenset(("get", "post", "put", "patch", "delete", "options", "any", "match", "view", "resource"))


class Edge:
    __slots__ = ("caller", "callee", "line", "kind", "file")

    def __init__(self, caller, callee, line, kind, file):
        self.caller = caller
        self.callee = callee
        self.line = line
        self.kind = kind
        self.file = file

    def __repr__(self):
        return "Edge(%s -> %s, %s, line %d)" % (self.caller, self.callee, self.kind, self.line)


class IncludeSite:
    __slots__ = ("file", "line", "unit", "targets", "dynamic", "pattern", "broad", "kind")

    def __init__(self, file, line, unit, targets, dynamic, pattern, broad, kind):
        self.file = file          # FileInfo of the including file
        self.line = line
        self.unit = unit          # key of the unit containing the include
        self.targets = targets    # [abs path]
        self.dynamic = dynamic    # path had a run-time part
        self.pattern = pattern    # glob-like pattern for dynamic includes ("*" = run-time part)
        self.broad = broad        # matched too many files; targets dropped
        self.kind = kind          # include / include_once / require / require_once

    def __repr__(self):
        return "IncludeSite(%s:%d -> %s)" % (self.file.rel, self.line, [os.path.basename(t) for t in self.targets])


class CallGraph:
    MAX_DYNAMIC_TARGETS = 40

    def __init__(self, project):
        self.p = project
        self.out = {}         # caller -> [Edge]
        self.inc = {}         # callee -> [Edge]
        self._files_norm = None

    # ----------------------------------------------------------------- api
    def callees_of(self, key):
        return list(self.out.get(key, ()))

    def callers_of(self, key):
        return list(self.inc.get(key, ()))

    def edges(self):
        for es in self.out.values():
            yield from es

    def _add(self, caller, callee, line, kind, fi):
        if not callee:
            return
        e = Edge(caller, callee, line, kind, fi)
        self.out.setdefault(caller, []).append(e)
        self.inc.setdefault(callee, []).append(e)

    # --------------------------------------------------------------- build
    def build(self):
        self.p.includes = []
        for rec in list(self.p.functions.values()):
            self._unit(rec)

    def _unit(self, rec):
        u = _Unit(self, rec)
        u.run()

    # ------------------------------------------------------- include paths
    def files_norm(self):
        if self._files_norm is None:
            self._files_norm = sorted(self.p.files)
            self._by_base = {}
            for f in self._files_norm:
                self._by_base.setdefault(os.path.basename(f), []).append(f)
            self._memo = {}
        return self._files_norm

    def _candidates(self, full):
        """Files that can match a pattern; narrowed by a literal file name when there is one."""
        self.files_norm()
        last = full.rsplit("/", 1)[-1]
        if WILD not in last and last:
            return self._by_base.get(last, [])
        return self._files_norm

    def resolve_include(self, parts, fi):
        """parts: list of str / WILD. Returns (targets, dynamic, pattern, broad)."""
        if not parts or all(x == WILD for x in parts):
            return [], True, "*", False
        dynamic = WILD in parts
        s = "".join(parts)
        bases = []
        if os.path.isabs(s.replace(WILD, "x")):
            bases = [""]
        else:
            bases = [os.path.dirname(fi.path), self.p.root]
        if not dynamic:
            for b in bases:
                cand = os.path.normpath(os.path.join(b, s)) if b else os.path.normpath(s)
                if os.path.isfile(cand):
                    return [cand], False, s, False
            return [], False, s, False
        # dynamic: literal text with run-time holes; match against project files
        lit = s.replace(WILD, "")
        if "/" not in lit and not lit.endswith((".php", ".inc", ".phtml")) and len(lit) < 4:
            return [], True, s.replace(WILD, "*"), False
        targets = []
        if s.startswith(WILD):
            # unknown root (e.g. DOL_DOCUMENT_ROOT . '/core/lib/x.php'): any directory prefix
            rest = s.lstrip(WILD)
            if rest.count("/") < 1 or len(rest.replace(WILD, "")) < 6:
                return [], True, s.replace(WILD, "*"), False
            bases = [None]
        for b in bases:
            if b is None:
                full = os.path.normpath(s.lstrip(WILD))
                tail = "[^/]*".join(re.escape(x) for x in full.split(WILD))
                rxs = "^(?:.*/)?" + tail.lstrip("/") + "$"
            else:
                full = os.path.normpath(os.path.join(b, s)) if b else os.path.normpath(s)
                rxs = "^" + "[^/]*".join(re.escape(x) for x in full.split(WILD)) + "$"
            self.files_norm()
            hit = self._memo.get(rxs)
            if hit is None:
                rx = re.compile(rxs)
                hit = [f for f in self._candidates(full) if rx.match(f)]
                self._memo[rxs] = hit
            for f in hit:
                if f not in targets:
                    targets.append(f)
            if targets:
                break
        broad = len(targets) > self.MAX_DYNAMIC_TARGETS
        return ([] if broad else targets), True, s.replace(WILD, "*"), broad


class _Unit:
    """Walks one unit's body in source order, tracking simple variable types and
    string values, and records edges and include sites."""

    def __init__(self, cg, rec):
        self.cg = cg
        self.p = cg.p
        self.rec = rec
        self.fi = rec.file
        self.ctx = rec.ctx
        self.cls = rec.cls
        self.types = {}       # var name -> [fq class]
        self.strs = {}        # var name -> [tuple of parts]: possible string values
        # assignments that always run (statement directly in the unit body):
        # these replace a variable's value; any other assignment adds a possibility
        self.top = {id(s.expr) for s in rec.body if s is not None and s.kind == "ExprStmt"}
        if self.cls:
            self.types["this"] = [self.cls]
        doc = parse_doc(rec.node.get("doc")) if rec.node is not None else {"param": {}}
        for prm in rec.params or []:
            names = [n for n in (prm.type.names if prm.type is not None else [])] + \
                type_names(doc["param"].get(prm.name))
            t = self.p._resolve_types(names, self.ctx)
            if t:
                self.types[prm.name] = t

    def run(self):
        self.stmts(self.rec.body)

    # ------------------------------------------------------------ traversal
    def stmts(self, body):
        for s in body:
            if s is None:
                continue
            d = s.get("doc")
            if d:
                for typ, name in parse_doc(d)["var"]:
                    if name:
                        t = self.p._resolve_types(type_names(typ), self.ctx)
                        if t:
                            self.types[name] = t
            self.node(s)

    def node(self, n):
        stack = [n]
        while stack:
            x = stack.pop()
            if x is None:
                continue
            k = x.kind
            if k in ("Closure", "ArrowFn"):
                key = self.p.function_key_for_node(x)
                if key:
                    self.cg._add(self.rec.key, key, x.line, "defines", self.fi)
                continue
            if k in ("Function", "Class"):
                continue
            d = x.__dict__.get("doc")
            if d and k not in ("Param", "Method", "Property"):
                for typ, name in parse_doc(d)["var"]:
                    if name:
                        t = self.p._resolve_types(type_names(typ), self.ctx)
                        if t:
                            self.types[name] = t
            if k == "Assign" or k == "AssignRef":
                self.assign(x)
            elif k == "Foreach":
                self.foreach(x)
            elif k == "Call":
                self.call(x)
            elif k == "StaticCall":
                self.static_call(x)
            elif k == "MethodCall":
                self.method_call(x)
            elif k == "New":
                self.new(x)
            elif k == "Include":
                self.include(x)
            elif k == "Global":
                for v in x.vars:
                    if v.kind == "Var" and isinstance(v.name, str):
                        self.strs.pop(v.name, None)
            kids = list(x.children())
            kids.reverse()
            stack.extend(kids)

    # ------------------------------------------------------------- inference
    def infer(self, e, depth=0):
        """Possible classes of an expression's value (fq names)."""
        if e is None or depth > 6:
            return []
        k = e.kind
        if k == "Var":
            return self.types.get(e.name, []) if isinstance(e.name, str) else []
        if k == "New":
            if e.cls.kind == "Name":
                return [self.p.resolve_class(e.cls.name, self.ctx)]
            if e.cls.kind == "Class" and getattr(e.cls, "sym", None):
                return [e.cls.sym.fq]
            return []
        if k == "Clone":
            return self.infer(e.expr, depth + 1)
        if k == "PropFetch" and isinstance(e.name, str):
            out = []
            for c in self.infer(e.obj, depth + 1):
                out.extend(self.p.prop_types(c, e.name))
            return out
        if k == "StaticProp" and isinstance(e.name, str) and e.cls.kind == "Name":
            return self.p.prop_types(self.p.resolve_class(e.cls.name, self.ctx), e.name)
        if k == "MethodCall" and isinstance(e.name, str):
            out = []
            for m in self.methods_for(e.obj, e.name, depth + 1)[0]:
                out.extend(self.rtypes(m))
            return out
        if k == "StaticCall" and isinstance(e.name, str) and e.cls.kind == "Name":
            m = self.p.method_lookup(self.p.resolve_class(e.cls.name, self.ctx), e.name)
            return self.rtypes(m) if m else []
        if k == "Call" and e.func.kind == "Name":
            f = self.p.resolve_function(e.func.name, self.ctx)
            return list(f.rtypes) if f else []
        if k == "Ternary":
            return self.infer(e.then or e.cond, depth + 1) + self.infer(e.else_, depth + 1)
        if k == "BinOp" and e.op == "??":
            return self.infer(e.left, depth + 1) + self.infer(e.right, depth + 1)
        return []

    def rtypes(self, m):
        if m is None:
            return []
        return [m.cls.fq if t.lower() in ("static", "self") else t for t in m.rtypes]

    def methods_for(self, obj, name, depth=0):
        """(methods, kind) for obj->name()."""
        types = self.infer(obj, depth)
        found, kind = [], "method"
        for t in types:
            cls = self.p.get_class(t)
            if cls is None:
                continue
            m = self.p.method_lookup(t, name)
            if m is not None and not m.abstract and cls.type != "interface":
                found.append(m)
            else:
                impls = self.p.implementations(t, name)
                if impls:
                    found.extend(impls)
                    kind = "method-impl"
                elif m is not None:
                    found.append(m)
        return found, kind

    # ----------------------------------------------------------- handlers
    def assign(self, a):
        tgt = a.target
        if tgt.kind == "Var" and isinstance(tgt.name, str):
            name = tgt.name
            if a.kind == "Assign" and a.op != "=" and a.op != ".=":
                self.strs.pop(name, None)
                return
            t = self.infer(a.value)
            if t:
                self.types[name] = t
            v = a.value
            stringy = v.kind in ("String", "Interp", "MagicConst", "Name", "Int", "Ternary") or \
                (v.kind == "BinOp" and v.op in (".", "??")) or \
                (v.kind == "Call" and v.func.kind == "Name" and v.func.name.lower().lstrip("\\") in _STR_FUNCS) or \
                (v.kind == "Var" and isinstance(v.name, str) and v.name in self.strs)
            if a.kind == "Assign" and a.op == ".=":
                prev = self.strs.get(name, [(WILD,)])
                alts = _concat(prev, self.eval_alts(v))
            elif stringy:
                alts = self.eval_alts(v)
            else:
                alts = [(WILD,)]
            if id(a) in self.top or name not in self.strs:
                self.strs[name] = alts
            else:                                   # conditional assignment: one more possibility
                merged = list(self.strs[name])
                for x in alts:
                    if x not in merged:
                        merged.append(x)
                self.strs[name] = merged if len(merged) <= _MAX_ALTS else [(WILD,)]

    def foreach(self, f):
        if f.value.kind == "Var" and isinstance(f.value.name, str):
            self.strs.pop(f.value.name, None)
            d = f.get("doc")
            if d:
                for typ, name in parse_doc(d)["var"]:
                    if name == f.value.name:
                        self.types[name] = self.p._resolve_types(type_names(typ), self.ctx)

    def call(self, c):
        fn = c.func
        line = c.line
        if fn.kind == "Name":
            name = fn.name
            sym = self.p.resolve_function(name, self.ctx)
            if sym is not None:
                self.cg._add(self.rec.key, sym.key, line, "call", self.fi)
            low = name.lstrip("\\").lower()
            idx = _CALLBACK_ARG.get(low)
            if idx is not None and len(c.args) > idx:
                for key in self.callable_targets(c.args[idx].value):
                    self.cg._add(self.rec.key, key, line, "callback", self.fi)
            if low == "register_rest_route" and len(c.args) >= 3:
                for key in self._rest_callbacks(c.args[2].value):
                    self.cg._add(self.rec.key, key, line, "callback", self.fi)
        elif fn.kind in ("Closure", "ArrowFn"):
            key = self.p.function_key_for_node(fn)
            if key:
                self.cg._add(self.rec.key, key, line, "call", self.fi)
        elif fn.kind == "Var" and isinstance(fn.name, str):
            pass   # $f() — dynamic; left to later layers

    def _rest_callbacks(self, arr):
        out = []
        if arr.kind != "Array":
            return out
        for it in arr.items:
            if it.key is not None and it.key.kind == "String" and it.key.value in ("callback", "permission_callback"):
                out.extend(self.callable_targets(it.value))
            elif it.value.kind == "Array":
                out.extend(self._rest_callbacks(it.value))
        return out

    def callable_targets(self, e):
        """Unit keys a PHP callable expression refers to."""
        if e is None:
            return []
        k = e.kind
        if k in ("Closure", "ArrowFn"):
            key = self.p.function_key_for_node(e)
            return [key] if key else []
        if k == "String":
            v = e.value.lstrip("\\")
            if "::" in v:
                cls, _, m = v.partition("::")
                ms = self.p.method_lookup(cls, m)
                return [ms.key] if ms else []
            if "@" in v:          # Laravel "Controller@method"
                cls, _, m = v.partition("@")
                ms = self.p.method_lookup(self.p.resolve_class(cls, self.ctx), m) or self.p.method_lookup(cls, m)
                return [ms.key] if ms else []
            f = self.p.funcs.get(v.lower())
            return [f.key] if f else []
        if k == "Array" and len(e.items) == 2 and e.items[0].key is None:
            target, meth = e.items[0].value, e.items[1].value
            if meth.kind != "String":
                return []
            classes = []
            if target.kind == "ClassConst" and target.name.lower() == "class" and target.cls.kind == "Name":
                classes = [self.p.resolve_class(target.cls.name, self.ctx)]
            elif target.kind == "String":
                classes = [target.value.lstrip("\\")]
            else:
                classes = self.infer(target)
            out = []
            for c in classes:
                ms = self.p.method_lookup(c, meth.value)
                if ms:
                    out.append(ms.key)
            return out
        if k == "Call" and e.get("callable"):
            if e.func.kind == "Name":
                f = self.p.resolve_function(e.func.name, self.ctx)
                return [f.key] if f else []
        if k == "MethodCall" and e.get("callable") and isinstance(e.name, str):
            return [m.key for m in self.methods_for(e.obj, e.name)[0]]
        if k == "StaticCall" and e.get("callable") and isinstance(e.name, str) and e.cls.kind == "Name":
            ms = self.p.method_lookup(self.p.resolve_class(e.cls.name, self.ctx), e.name)
            return [ms.key] if ms else []
        return []

    def static_call(self, c):
        if not isinstance(c.name, str):
            return
        if c.cls.kind == "Name":
            low = c.cls.name.lower()
            fq = self.p.resolve_class(c.cls.name, self.ctx)
            if low == "parent" and self.cls:
                cs = self.p.get_class(self.cls)
                fq = cs.parent if cs and cs.parent else fq
            ms = self.p.method_lookup(fq, c.name)
            if ms is not None:
                self.cg._add(self.rec.key, ms.key, c.line, "static", self.fi)
            # Laravel routes: Route::get('/x', [Ctl::class, 'm']) / 'Ctl@m'
            if fq.lower().endswith("route") and c.name.lower() in _ROUTE_METHODS and c.args:
                idx = 2 if c.name.lower() == "match" else 1
                if len(c.args) > idx:
                    for key in self.callable_targets(c.args[idx].value):
                        self.cg._add(self.rec.key, key, c.line, "route", self.fi)
        else:
            for t in self.infer(c.cls):
                ms = self.p.method_lookup(t, c.name)
                if ms is not None:
                    self.cg._add(self.rec.key, ms.key, c.line, "static", self.fi)

    def method_call(self, c):
        if not isinstance(c.name, str):
            return
        found, kind = self.methods_for(c.obj, c.name)
        if found:
            for m in found:
                self.cg._add(self.rec.key, m.key, c.line, kind, self.fi)
            return
        cands = self.p.methods_by_name.get(c.name.lower(), [])
        if len(cands) == 1:
            self.cg._add(self.rec.key, cands[0].key, c.line, "method-name", self.fi)

    def new(self, n):
        fqs = self.infer(n)
        for fq in fqs:
            ms = self.p.method_lookup(fq, "__construct")
            if ms is not None:
                self.cg._add(self.rec.key, ms.key, n.line, "new", self.fi)

    def include(self, inc):
        targets, dynamic, patterns, broad = [], False, [], False
        for parts in self.eval_alts(inc.expr):
            t, d, pat, b = self.cg.resolve_include(list(parts), self.fi)
            for x in t:
                if x not in targets:
                    targets.append(x)
            dynamic = dynamic or d
            broad = broad or b
            if pat not in patterns:
                patterns.append(pat)
        site = IncludeSite(self.fi, inc.line, self.rec.key, targets, dynamic, " | ".join(patterns), broad, inc.type)
        inc.site = site
        self.p.includes.append(site)
        for t in targets:
            rel = os.path.relpath(t, self.p.root)
            self.cg._add(self.rec.key, "file:" + rel, inc.line, "include", self.fi)

    # ---------------------------------------------------------- string eval
    def eval_str(self, e):
        """Single best static value (first alternative) as parts; kept for callers
        that need one path."""
        return list(self.eval_alts(e)[0])

    def eval_alts(self, e, depth=0):
        """Possible static values of a path-like expression: a list of tuples of
        parts, each part a literal string or WILD (a run-time value)."""
        if e is None or depth > 12:
            return [(WILD,)]
        k = e.kind
        if k == "String" or k == "Int":
            return [(e.value,)]
        if k == "Interp":
            out = [()]
            for p in e.parts:
                out = _concat(out, self.eval_alts(p, depth + 1))
            return out
        if k == "BinOp" and e.op == ".":
            return _concat(self.eval_alts(e.left, depth + 1), self.eval_alts(e.right, depth + 1))
        if k == "BinOp" and e.op == "??":
            return _union(self.eval_alts(e.left, depth + 1), self.eval_alts(e.right, depth + 1))
        if k == "Ternary":
            return _union(self.eval_alts(e.then or e.cond, depth + 1), self.eval_alts(e.else_, depth + 1))
        if k == "MagicConst":
            if e.name == "__dir__":
                return [(os.path.dirname(self.fi.path),)]
            if e.name == "__file__":
                return [(self.fi.path,)]
            return [(WILD,)]
        if k == "Var" and isinstance(e.name, str):
            v = self.strs.get(e.name)
            return list(v) if v is not None else [(WILD,)]
        if k == "Name":
            return self.const_alts(e.name, depth)
        if k == "Call" and e.func.kind == "Name" and e.args:
            fname = e.func.name.lstrip("\\").lower()
            if fname in _STR_FUNCS:
                out = []
                for inner in self.eval_alts(e.args[0].value, depth + 1):
                    if WILD in inner:
                        if fname in ("strtolower", "trim", "strval", "realpath"):
                            out.append(inner)
                        else:
                            out.append((WILD,))
                        continue
                    s = "".join(inner)
                    if fname == "dirname":
                        levels = 1
                        if len(e.args) > 1 and e.args[1].value.kind == "Int":
                            try:
                                levels = int(e.args[1].value.value, 0)
                            except ValueError:
                                levels = 1
                        for _ in range(max(1, levels)):
                            s = os.path.dirname(s)
                    elif fname == "trailingslashit":
                        s = s.rstrip("/\\") + "/"
                    elif fname == "untrailingslashit":
                        s = s.rstrip("/\\")
                    elif fname == "basename":
                        s = os.path.basename(s)
                    elif fname == "plugin_dir_path":
                        s = os.path.dirname(s) + "/"
                    elif fname == "strtolower":
                        s = s.lower()
                    elif fname == "trim":
                        s = s.strip()
                    out.append((s,))
                return _dedupe(out)
        return [(WILD,)]

    def const_alts(self, name, depth):
        defs = self.p.const_values(name, self.fi)
        if not defs:
            return [(WILD,)]
        vals = []
        for value, fi, ctx in defs[:6]:
            sub = _Unit.__new__(_Unit)
            sub.cg, sub.p, sub.fi, sub.ctx, sub.cls = self.cg, self.p, fi, ctx, None
            sub.strs, sub.types, sub.rec, sub.top = {}, {}, self.rec, set()
            for alt in sub.eval_alts(value, depth + 1):
                if alt not in vals:
                    vals.append(alt)
        return vals if len(vals) <= _MAX_ALTS else [(WILD,)]


_MAX_ALTS = 16
_STR_FUNCS = frozenset(("dirname", "realpath", "strval", "trailingslashit", "untrailingslashit", "basename",
                        "plugin_dir_path", "strtolower", "trim"))


def _dedupe(alts):
    out = []
    for a in alts:
        if a not in out:
            out.append(a)
    return out


def _concat(left, right):
    out = []
    for a in left:
        for b in right:
            x = a + b
            if x not in out:
                out.append(x)
            if len(out) > _MAX_ALTS:
                return [(WILD,)]
    return out or [(WILD,)]


def _union(a, b):
    out = _dedupe(list(a) + list(b))
    return out if len(out) <= _MAX_ALTS else [(WILD,)]
