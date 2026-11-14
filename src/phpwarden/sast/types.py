"""Layer 3: flow-sensitive type inference.

Per unit (function, method, closure, file), variables map to sets of
fully-qualified class names. Types come from `new`, typed parameters, returns
and properties, docblocks (@var/@param/@return/@property, including generics
such as Collection<User>, array<int, User>, User[] for element types),
self/static, method return types through the class hierarchy, and framework
factories (Laravel app()/resolve()/request()/facades, container get(X::class)).

The environment is a plain dict; the taint walker copies it at branches and
joins it after (`join`), which makes the inference flow-sensitive. Element
types of collections are stored under the key "[]name".
"""
from __future__ import annotations

import re

from .symbols import parse_doc, type_names

_GENERIC = re.compile(r"^\s*\??\\?([A-Za-z_][\w\\]*)\s*<(.+)>\s*$")
_ARRAY_OF = re.compile(r"^\s*\??\\?([A-Za-z_][\w\\]*)\[\]\s*$")
_COLLECTIONS = frozenset({"array", "list", "iterable", "non-empty-array", "non-empty-list", "collection",
                          "arrayaccess", "traversable", "iterator", "generator", "arrayiterator", "arrayobject",
                          "illuminate\\support\\collection", "illuminate\\database\\eloquent\\collection",
                          "doctrine\\common\\collections\\collection", "doctrine\\common\\collections\\arraycollection"})

LARAVEL_FACADE_ROOTS = {
    "request": "Illuminate\\Http\\Request", "db": "Illuminate\\Database\\DatabaseManager",
    "http": "Illuminate\\Http\\Client\\Factory", "storage": "Illuminate\\Filesystem\\FilesystemManager",
    "redirect": "Illuminate\\Routing\\Redirector", "response": "Illuminate\\Routing\\ResponseFactory",
    "cache": "Illuminate\\Cache\\CacheManager", "file": "Illuminate\\Filesystem\\Filesystem",
}
SERVICE_IDS = {"request": "Illuminate\\Http\\Request", "db": "Illuminate\\Database\\DatabaseManager",
               "files": "Illuminate\\Filesystem\\Filesystem", "redirect": "Illuminate\\Routing\\Redirector",
               "http": "Illuminate\\Http\\Client\\Factory"}
_FACTORY_FUNCS = frozenset({"app", "resolve", "make"})
_REQUEST_HELPER = "Illuminate\\Http\\Request"


def split_generic(typ):
    """('Collection', ['User']) for 'Collection<User>' / ('array', ['User']) for 'User[]'."""
    if not typ:
        return None, []
    for alt in typ.split("|"):
        m = _GENERIC.match(alt)
        if m:
            args = [a.strip() for a in m.group(2).split(",")]
            return m.group(1), type_names(args[-1]) if args else []
        m = _ARRAY_OF.match(alt)
        if m:
            return "array", [m.group(1)]
    return None, []


def join(a, b):
    """Union of two type environments (after an if/else)."""
    if a is b:
        return a
    out = dict(a)
    for k, v in b.items():
        if k in out:
            if out[k] != v:
                out[k] = out[k] | v
        else:
            out[k] = v
    return out


class Types:
    MAX_DEPTH = 6

    def __init__(self, project, rec):
        self.p = project
        self.rec = rec
        self.ctx = rec.ctx
        self.cls = rec.cls

    # ----------------------------------------------------------- set-up
    def initial(self):
        env = {}
        if self.cls:
            env["this"] = frozenset([self.cls])
        node = self.rec.node
        doc = parse_doc(node.get("doc")) if node is not None else {"param": {}}
        for prm in self.rec.params or []:
            names = list(prm.type.names) if prm.type is not None else []
            dtyp = doc["param"].get(prm.name)
            names += type_names(dtyp)
            t = self.p._resolve_types(names, self.ctx)
            if t:
                env[prm.name] = frozenset(t)
            base, elem = split_generic(dtyp)
            if elem:
                et = self.p._resolve_types(elem, self.ctx)
                if et:
                    env["[]" + prm.name] = frozenset(et)
        return env

    def doc_vars(self, doc, env):
        """Apply inline `/** @var Type $x */` annotations."""
        if not doc:
            return
        for typ, name in parse_doc(doc)["var"]:
            if not name:
                continue
            t = self.p._resolve_types(type_names(typ), self.ctx)
            base, elem = split_generic(typ)
            if base is not None and base.lower() in _COLLECTIONS or (base == "array"):
                t = [x for x in t if x not in elem]
            if t:
                env[name] = frozenset(t)
            if elem:
                et = self.p._resolve_types(elem, self.ctx)
                if et:
                    env["[]" + name] = frozenset(et)

    # -------------------------------------------------------- inference
    def infer(self, e, env, depth=0):
        """Possible classes (fq) of an expression's value."""
        if e is None or depth > self.MAX_DEPTH:
            return frozenset()
        k = e.kind
        if k == "Var":
            return env.get(e.name, frozenset()) if isinstance(e.name, str) else frozenset()
        if k == "New":
            c = e.cls
            if c.kind == "Name":
                return frozenset([self.p.resolve_class(c.name, self.ctx)])
            if c.kind == "Class" and getattr(c, "sym", None):
                return frozenset([c.sym.fq])
            return frozenset()
        if k == "Clone":
            return self.infer(e.expr, env, depth + 1)
        if k == "Assign":
            return self.infer(e.value, env, depth + 1)
        if k == "PropFetch" and isinstance(e.name, str):
            out = set()
            for c in self.infer(e.obj, env, depth + 1):
                out.update(self.p.prop_types(c, e.name))
            local = env.get("this->" + e.name) if e.obj.kind == "Var" and e.obj.name == "this" else None
            if local:
                out.update(local)
            return frozenset(out)
        if k == "StaticProp" and isinstance(e.name, str) and e.cls.kind == "Name":
            return frozenset(self.p.prop_types(self.p.resolve_class(e.cls.name, self.ctx), e.name))
        if k == "ArrayDim":
            if e.var.kind == "Var" and isinstance(e.var.name, str):
                return env.get("[]" + e.var.name, frozenset())
            return frozenset()
        if k == "MethodCall" and isinstance(e.name, str):
            out = set()
            lname = e.name.lower()
            for m in self.methods_for(e.obj, e.name, env, depth + 1):
                out.update(self.rtypes(m))
            if not out:
                recv = self.infer(e.obj, env, depth + 1)
                # fluent framework objects: $request->query (bag), container ->get(X::class)
                if lname in ("get", "make", "resolve") and e.args:
                    out.update(self._class_arg(e.args[0].value))
                elif any(r.lower().endswith(("\\builder", "\\querybuilder")) for r in recv) and lname.startswith(
                        ("where", "orwhere", "select", "orderby", "join", "leftjoin", "groupby", "having", "limit",
                         "offset", "with")):
                    out.update(recv)
            return frozenset(out)
        if k == "StaticCall" and isinstance(e.name, str) and e.cls.kind == "Name":
            fq = self.p.resolve_class(e.cls.name, self.ctx)
            m = self.p.method_lookup(fq, e.name)
            if m is not None:
                return frozenset(self.rtypes(m, fq))
            short = e.cls.name.rsplit("\\", 1)[-1].lower()
            if short == "app" and e.name.lower() in ("make", "get") and e.args:
                return frozenset(self._class_arg(e.args[0].value))
            if e.name.lower() in ("create", "find", "findorfail", "first", "firstorfail", "make", "firstorcreate",
                                  "updateorcreate", "firstornew", "query", "where"):
                cs = self.p.get_class(fq)
                if cs is not None:
                    return frozenset([fq])
            return frozenset()
        if k == "Call" and e.func.kind == "Name":
            name = e.func.name.lstrip("\\").lower()
            if name in _FACTORY_FUNCS and e.args:
                return frozenset(self._class_arg(e.args[0].value))
            if name == "request" and not e.args:
                return frozenset([_REQUEST_HELPER])
            f = self.p.resolve_function(e.func.name, self.ctx)
            return frozenset(f.rtypes) if f else frozenset()
        if k == "Ternary":
            return self.infer(e.then or e.cond, env, depth + 1) | self.infer(e.else_, env, depth + 1)
        if k == "BinOp" and e.op == "??":
            return self.infer(e.left, env, depth + 1) | self.infer(e.right, env, depth + 1)
        if k == "Match":
            out = set()
            for a in e.arms:
                out.update(self.infer(a.body, env, depth + 1))
            return frozenset(out)
        return frozenset()

    def _class_arg(self, a):
        if a is None:
            return []
        if a.kind == "ClassConst" and isinstance(a.name, str) and a.name.lower() == "class" and a.cls.kind == "Name":
            return [self.p.resolve_class(a.cls.name, self.ctx)]
        if a.kind == "String":
            v = a.value.lstrip("\\")
            if v.lower() in SERVICE_IDS:
                return [SERVICE_IDS[v.lower()]]
            if "\\" in v:
                return [v]
        return []

    def rtypes(self, m, called_on=None):
        out = []
        for t in m.rtypes:
            if t.lower() in ("static", "self", "$this"):
                out.append(called_on or m.cls.fq)
            else:
                out.append(t)
        return out

    def methods_for(self, obj, name, env, depth=0):
        """Methods that obj->name() can dispatch to, using the inferred types."""
        found = []
        for t in self.infer(obj, env, depth):
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
                elif m is not None:
                    found.append(m)
        return found

    def foreach(self, f, env):
        """Element types flow into the foreach value variable."""
        v = f.value
        if v is not None and v.kind == "Var" and isinstance(v.name, str):
            s = f.subject
            elem = frozenset()
            if s.kind == "Var" and isinstance(s.name, str):
                elem = env.get("[]" + s.name, frozenset())
            elif s.kind in ("MethodCall", "StaticCall", "PropFetch"):
                elem = self._elem_of_expr(s, env)
            if elem:
                env[v.name] = elem
            else:
                env.pop(v.name, None)
            d = f.get("doc")
            if d:
                self.doc_vars(d, env)

    def _elem_of_expr(self, e, env):
        """Element types of a method's declared return (@return Collection<User>)."""
        if e.kind == "MethodCall" and isinstance(e.name, str):
            out = set()
            for m in self.methods_for(e.obj, e.name, env):
                doc = parse_doc(m.node.get("doc"))
                _b, elem = split_generic(doc["return"])
                out.update(self.p._resolve_types(elem, m.cls.ctx))
            return frozenset(out)
        if e.kind == "PropFetch" and isinstance(e.name, str):
            out = set()
            for c in self.infer(e.obj, env):
                cs = self.p.get_class(c)
                ps = cs.props.get(e.name) if cs is not None else None
                if ps is not None and ps.node is not None:
                    pnode = ps.node
                    owner = cs.node
                    # docblock is on the Property member, not the PropItem
                    for mem in (owner.members if owner is not None else []):
                        if mem.kind == "Property" and any(pi is pnode for pi in mem.props):
                            for typ, _nm in parse_doc(mem.get("doc"))["var"]:
                                _b, elem = split_generic(typ)
                                out.update(self.p._resolve_types(elem, cs.ctx))
            return frozenset(out)
        return frozenset()

    def assign(self, target, value, env):
        if target.kind == "Var" and isinstance(target.name, str):
            t = self.infer(value, env)
            if t:
                env[target.name] = t
            else:
                env.pop(target.name, None)
            if value is not None and value.kind == "Var" and isinstance(value.name, str):
                el = env.get("[]" + value.name)
                if el:
                    env["[]" + target.name] = el
        elif target.kind == "PropFetch" and isinstance(target.name, str) and target.obj.kind == "Var" \
                and target.obj.name == "this":
            t = self.infer(value, env)
            if t:
                env["this->" + target.name] = t


# ------------------------------------------------------- call-graph refinement
def refine_callgraph(project):
    """Replace name-only method edges ('method-name') by typed ones where the
    flow-sensitive types resolve the receiver. Returns (replaced, added)."""
    cg = project.callgraph
    if cg is None:
        return 0, 0
    replaced = added = 0
    for rec in list(project.iter_functions()):
        w = _TypeWalker(project, rec)
        w.run()
        if not w.resolved:
            continue
        old = cg.out.get(rec.key, [])
        keep = []
        drop_lines = {(line, name) for (line, name) in w.resolved}
        for e in old:
            if e.kind == "method-name":
                mname = e.callee.rsplit("::", 1)[-1]
                if (e.line, mname) in drop_lines:
                    lst = cg.inc.get(e.callee, [])
                    if e in lst:
                        lst.remove(e)
                    replaced += 1
                    continue
            keep.append(e)
        cg.out[rec.key] = keep
        have = {(e.callee, e.line) for e in keep}
        for (line, _name), methods in w.resolved.items():
            for m in methods:
                if (m.key, line) not in have:
                    cg._add(rec.key, m.key, line, "method", rec.file)
                    have.add((m.key, line))
                    added += 1
    return replaced, added


class _TypeWalker:
    def __init__(self, project, rec):
        self.t = Types(project, rec)
        self.rec = rec
        self.resolved = {}

    def run(self):
        env = self.t.initial()
        self.block(self.rec.body, env)

    def block(self, body, env):
        for s in body or []:
            if s is None:
                continue
            self.stmt(s, env)
        return env

    def stmt(self, s, env):
        k = s.kind
        d = s.get("doc")
        if d:
            self.t.doc_vars(d, env)
        if k == "If":
            self.expr(s.cond, env)
            outs = [self.block(s.body, dict(env))]
            for ei in s.elifs or []:
                self.expr(ei.cond, env)
                outs.append(self.block(ei.body, dict(env)))
            outs.append(self.block(s.else_ or [], dict(env)) if s.else_ else dict(env))
            merged = outs[0]
            for o in outs[1:]:
                merged = join(merged, o)
            env.clear()
            env.update(merged)
            return
        if k in ("While", "For", "DoWhile"):
            for part in ("cond", "init", "step"):
                v = s.get(part)
                if isinstance(v, list):
                    for x in v:
                        self.expr(x, env)
                elif v is not None:
                    self.expr(v, env)
            inner = self.block(s.body, dict(env))
            env.update(join(env, inner))
            return
        if k == "Foreach":
            self.expr(s.subject, env)
            inner = dict(env)
            self.t.foreach(s, inner)
            self.block(s.body, inner)
            env.update(join(env, inner))
            return
        if k == "Switch":
            self.expr(s.cond, env)
            merged = dict(env)
            for c in s.cases:
                merged = join(merged, self.block(c.body, dict(env)))
            env.clear()
            env.update(merged)
            return
        if k == "Try":
            self.block(s.body, env)
            for c in s.catches:
                inner = dict(env)
                if c.var is not None and getattr(c.var, "name", None):
                    inner[c.var.name if isinstance(c.var.name, str) else ""] = frozenset(
                        self.t.p._resolve_types(list(c.types), self.t.ctx))
                env.update(join(env, self.block(c.body, inner)))
            if s.finally_:
                self.block(s.finally_, env)
            return
        if k in ("Block", "Declare"):
            self.block(s.body or [], env)
            return
        for ch in s.children():
            self.expr(ch, env)

    def expr(self, e, env):
        if e is None:
            return
        stack = [e]
        order = []
        while stack:
            x = stack.pop()
            if x is None or x.kind in ("Closure", "ArrowFn", "Class", "Function"):
                continue
            order.append(x)
            stack.extend(x.children())
        for x in reversed(order):
            if x.kind == "Assign" and x.op == "=":
                self.t.assign(x.target, x.value, env)
            elif x.kind == "MethodCall" and isinstance(x.name, str):
                ms = self.t.methods_for(x.obj, x.name, env)
                if ms:
                    self.resolved[(x.line, x.name.lower())] = ms
