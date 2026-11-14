"""Whole-program model: every file parsed, every symbol resolved.

    proj = Project.load("/path/to/app")            # parse + index + call graph
    proj.get_class("App\\\\Repo\\\\Users")           # ClassSym
    proj.method_lookup("App\\\\Repo\\\\Users", "find")  # MethodSym (through parents and traits)
    proj.resolve_function("esc_html", ctx)         # FuncSym
    proj.functions["f:app\\\\helper"]               # FunctionRec (functions, methods, closures, file code)
    proj.callgraph.callees_of(key) / callers_of(key)
    proj.includes                                  # resolved include/require sites

vendor/ is used for symbol resolution only: by default ("lazy") a vendor file is
parsed the first time one of its classes is needed (found through Composer's
autoload map), and files under vendor/ are flagged so later layers do not
report findings in them.
"""
from __future__ import annotations

import json
import os
import re

from .ast import Node, walk
from .parser import parse_file
from .symbols import (ClassSym, FuncSym, MethodSym, NameCtx, PropSym, node_type_names, parse_doc, qualify,
                      type_names)

SKIP_DIRS = frozenset((".git", ".svn", ".hg", "node_modules", ".idea", ".vscode"))
EXTS = (".php", ".phtml", ".inc", ".module", ".install", ".theme")


class FileInfo:
    __slots__ = ("path", "rel", "vendor", "stmts", "errors", "comments", "internal_error", "src", "ctx_root")

    def __init__(self, path, rel, vendor, res):
        self.path = path
        self.rel = rel
        self.vendor = vendor
        self.stmts = res.stmts
        self.errors = res.errors
        self.comments = res.comments
        self.internal_error = res.internal_error
        self.src = res.src
        self.ctx_root = None

    def __repr__(self):
        return "FileInfo(%s)" % self.rel


class FunctionRec:
    """A unit of code: a function, a method, a closure / arrow fn, or a file's
    top-level statements. `body` is a list of statements (an arrow fn's body is
    wrapped as [Return(expr)]); `params` are Param nodes."""
    __slots__ = ("key", "kind", "name", "node", "body", "params", "file", "ctx", "cls", "parent_key", "sym")

    def __init__(self, key, kind, name, node, body, params, file, ctx, cls=None, parent_key=None, sym=None):
        self.key = key
        self.kind = kind            # "function" | "method" | "closure" | "file"
        self.name = name
        self.node = node
        self.body = body
        self.params = params
        self.file = file
        self.ctx = ctx
        self.cls = cls              # fq class name for methods/closures in a class
        self.parent_key = parent_key
        self.sym = sym

    def __repr__(self):
        return "FunctionRec(%s)" % self.key


class Project:
    def __init__(self, root, vendor="lazy", max_files=60000, exclude=None, skip_tests=False):
        self.root = os.path.abspath(root)
        self.skip_tests = skip_tests         # leave test/tests dirs and *Test.php out of the model
        self.vendor_mode = vendor            # "lazy" | "all" | "none"
        self.max_files = max_files
        self.exclude = set(exclude or ())
        self.files = {}                      # abs path -> FileInfo
        self.classes = {}                    # fq lower -> ClassSym
        self.funcs = {}                      # fq lower -> FuncSym
        self.constants = {}                  # name (case-sensitive) -> [(value Node, FileInfo, ctx)]
        self.functions = {}                  # key -> FunctionRec
        self.methods_by_name = {}            # lower name -> [MethodSym]
        self.subclasses = {}                 # fq lower -> set(fq lower) of direct children / implementors
        self.autoload = []                   # [(kind, prefix, [dirs])] psr-4 / psr-0
        self.classmap_dirs = []
        self.autoload_files = []             # vendor "files" autoloads (helper functions), parsed eagerly
        self.includes = []
        self.callgraph = None
        self.truncated = False
        self._autoload_tried = set()
        self._node_keys = {}                 # id(closure node) -> key
        self._cache = {}                     # memo for method_lookup / implementations / ancestors

    # ----------------------------------------------------------------- load
    @classmethod
    def load(cls, root, build_callgraph=True, **kw):
        p = cls(root, **kw)
        p.scan()
        if build_callgraph:
            from .callgraph import CallGraph
            p.callgraph = CallGraph(p)
            p.callgraph.build()
        return p

    def scan(self):
        self._read_composer(self.root, vendor=False)
        vdir = os.path.join(self.root, "vendor")
        if os.path.isdir(vdir) and self.vendor_mode != "none":
            for d in sorted(os.listdir(vdir)):
                pd = os.path.join(vdir, d)
                if not os.path.isdir(pd) or d == "composer" or d == "bin":
                    continue
                for pk in sorted(os.listdir(pd)):
                    pkd = os.path.join(pd, pk)
                    if os.path.isfile(os.path.join(pkd, "composer.json")):
                        self._read_composer(pkd, vendor=True)
        for path in self._discover():
            self.add_file(path)
        if self.vendor_mode == "lazy":
            for path in self.autoload_files[:400]:
                self.add_file(path)
        if self.vendor_mode == "all" and os.path.isdir(vdir):
            for path in self._discover(vdir, inside_vendor=True):
                self.add_file(path)
        self._link_hierarchy()
        self._build_functions()

    def _discover(self, top=None, inside_vendor=False):
        top = top or self.root
        n = 0
        for d, dirs, fs in os.walk(top):
            rel_d = os.path.relpath(d, self.root)
            keep = []
            for x in sorted(dirs):
                if x in SKIP_DIRS:
                    continue
                if not inside_vendor and d == self.root and x == "vendor":
                    continue
                if os.path.join(rel_d, x).lstrip("./") in self.exclude:
                    continue
                if self.skip_tests and x.lower() in ("test", "tests"):
                    continue
                keep.append(x)
            dirs[:] = keep
            for f in sorted(fs):
                if self.skip_tests and f.endswith("Test.php"):
                    continue
                if f.endswith(EXTS):
                    n += 1
                    if n > self.max_files:
                        self.truncated = True
                        return
                    yield os.path.join(d, f)

    def is_vendor(self, path):
        rel = os.path.relpath(path, self.root)
        return rel == "vendor" or rel.startswith("vendor" + os.sep)

    def add_file(self, path):
        path = os.path.abspath(path)
        if path in self.files:
            return self.files[path]
        res = parse_file(path)
        self._cache.clear()                  # new symbols can change lookups
        fi = FileInfo(path, os.path.relpath(path, self.root), self.is_vendor(path), res)
        self.files[path] = fi
        self._index_file(fi)
        return fi

    # ------------------------------------------------------------- composer
    def _read_composer(self, base, vendor):
        try:
            with open(os.path.join(base, "composer.json"), encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return
        for section in ("autoload", "autoload-dev"):
            al = doc.get(section) or {}
            if not isinstance(al, dict):
                continue
            for kind in ("psr-4", "psr-0"):
                for prefix, dirs in (al.get(kind) or {}).items():
                    if isinstance(dirs, str):
                        dirs = [dirs]
                    self.autoload.append((kind, prefix, [os.path.normpath(os.path.join(base, x)) for x in dirs],
                                          vendor))
            for x in al.get("classmap") or []:
                self.classmap_dirs.append((os.path.normpath(os.path.join(base, x)), vendor))
            if vendor:
                for x in al.get("files") or []:
                    p = os.path.normpath(os.path.join(base, x))
                    if os.path.isfile(p):
                        self.autoload_files.append(p)

    def autoload_file(self, fq):
        """Candidate file for a class per the Composer autoload map, or None."""
        fqn = fq.lstrip("\\")
        best = None
        for kind, prefix, dirs, _v in self.autoload:
            if kind == "psr-4":
                if fqn.lower().startswith(prefix.lower()) or prefix == "":
                    rest = fqn[len(prefix):].replace("\\", os.sep) + ".php"
                    for d in dirs:
                        cand = os.path.join(d, rest)
                        if os.path.isfile(cand) and (best is None or len(prefix) > best[0]):
                            best = (len(prefix), cand)
            else:
                if fqn.lower().startswith(prefix.lower()) or prefix == "":
                    ns, _, cls = fqn.rpartition("\\")
                    rest = (ns.replace("\\", os.sep) + os.sep if ns else "") + cls.replace("_", os.sep) + ".php"
                    for d in dirs:
                        cand = os.path.join(d, rest)
                        if os.path.isfile(cand) and (best is None or len(prefix) > best[0]):
                            best = (len(prefix), cand)
        return best[1] if best else None

    # -------------------------------------------------------------- indexing
    def _index_file(self, fi):
        ctx = NameCtx("", None, None, None, fi)
        fi.ctx_root = ctx
        self._index_stmts(fi.stmts, fi, ctx)

    def _index_stmts(self, stmts, fi, ctx):
        for s in stmts:
            if s is None:
                continue
            k = s.kind
            if k == "Namespace":
                nctx = NameCtx(s.name or "", None, None, None, fi)
                s.ctx = nctx
                self._index_stmts(s.body, fi, nctx)
                continue
            if k == "Use":
                for u in s.uses:
                    alias = (u.alias or u.name.rsplit("\\", 1)[-1]).lower()
                    ctx.uses[u.type if u.type in ("function", "const") else "class"][alias] = u.name
                continue
            if k == "Class":
                self._index_class(s, fi, ctx)
                continue
            if k == "Function":
                fq = (ctx.namespace + "\\" + s.name) if ctx.namespace else s.name
                s.ctx = ctx
                doc = parse_doc(s.doc)
                rt = self._resolve_types(node_type_names(s.rtype) + type_names(doc["return"]), ctx)
                sym = FuncSym(fq, s, fi, ctx, rt)
                self.funcs.setdefault(fq.lower(), sym)
                s.sym = sym
                self._index_nested(s.body, fi, ctx)
                continue
            if k == "Const":
                for c in s.consts:
                    fq = (ctx.namespace + "\\" + c.name) if ctx.namespace else c.name
                    self.constants.setdefault(fq, []).append((c.value, fi, ctx))
                continue
            self._index_nested([s], fi, ctx)

    def _index_nested(self, stmts, fi, ctx):
        """Conditional declarations (function_exists guards, if-defined classes) and define() calls."""
        for n in walk(stmts):
            k = n.kind
            if k == "Call" and n.func.kind == "Name" and n.func.name.lower() in ("define", "\\define") and \
                    len(n.args) >= 2 and n.args[0].value.kind == "String":
                self.constants.setdefault(n.args[0].value.value.lstrip("\\"), []).append((n.args[1].value, fi, ctx))
            elif k == "Class" and n.name and not hasattr(n, "ctx"):
                self._index_class(n, fi, ctx)
            elif k == "Function" and not hasattr(n, "ctx"):
                fq = (ctx.namespace + "\\" + n.name) if ctx.namespace else n.name
                n.ctx = ctx
                doc = parse_doc(n.doc)
                sym = FuncSym(fq, n, fi, ctx, self._resolve_types(node_type_names(n.rtype) + type_names(doc["return"]), ctx))
                self.funcs.setdefault(fq.lower(), sym)
                n.sym = sym

    def _index_class(self, node, fi, ctx):
        fq = (ctx.namespace + "\\" + node.name) if ctx.namespace else node.name
        parent_fq = qualify(node.parent, ctx) if node.parent else None
        cctx = ctx.with_class(fq, parent_fq)
        node.ctx = cctx
        sym = ClassSym(fq, node, cctx, fi, fi.vendor)
        sym.parent = parent_fq
        sym.interfaces = [qualify(x, ctx) for x in node.interfaces]
        node.sym = sym
        cdoc = parse_doc(node.doc)
        for pname, ptype in cdoc["property"].items():
            sym.magic_props[pname] = self._resolve_types(type_names(ptype), cctx)
        for m in node.members:
            mk = m.kind
            if mk == "Method":
                doc = parse_doc(m.doc)
                rt = self._resolve_types(node_type_names(m.rtype) + type_names(doc["return"]), cctx)
                ms = MethodSym(m.name, sym, m, rt)
                m.sym = ms
                m.ctx = cctx
                sym.methods[m.name.lower()] = ms
                # promoted constructor parameters are properties
                if m.name.lower() == "__construct":
                    for p in m.params:
                        if p.flags:
                            sym.props[p.name] = PropSym(p.name, sym, self._resolve_types(
                                node_type_names(p.type) + type_names(doc["param"].get(p.name)), cctx), False, p)
                if m.body:
                    self._index_nested(m.body, fi, cctx)
            elif mk == "Property":
                doc = parse_doc(m.doc)
                dtypes = [t for t, nm in doc["var"]]
                for pi in m.props:
                    sym.props[pi.name] = PropSym(pi.name, sym, self._resolve_types(
                        node_type_names(m.type) + [x for t in dtypes for x in type_names(t)], cctx),
                        "static" in (m.flags or []), pi)
            elif mk == "ClassConst":
                for c in m.consts:
                    sym.consts[c.name] = c.value
            elif mk == "EnumCase":
                sym.consts[m.name] = m.value
            elif mk == "TraitUse":
                sym.traits.extend(qualify(t, cctx) for t in m.traits)
                sym.trait_adapt.extend(m.adaptations)
        self.classes.setdefault(fq.lower(), sym)

    def _resolve_types(self, names, ctx):
        out = []
        for n in names:
            low = n.lower()
            if low in ("self", "static", "$this", "this"):
                if ctx.cls:
                    out.append(ctx.cls)
                continue
            if low == "parent":
                if ctx.parent:
                    out.append(ctx.parent)
                continue
            q = qualify(n, ctx)
            if q and q.lower() not in ("int", "string", "bool", "float", "array", "mixed", "void", "null",
                                        "callable", "iterable", "object", "never", "false", "true"):
                out.append(q)
        seen = set()
        return [x for x in out if not (x.lower() in seen or seen.add(x.lower()))]

    def _link_hierarchy(self):
        self.subclasses = {}
        self.methods_by_name = {}
        for sym in list(self.classes.values()):
            for base in ([sym.parent] if sym.parent else []) + sym.interfaces:
                self.subclasses.setdefault(base.lower(), set()).add(sym.fq.lower())
            for lname, ms in sym.methods.items():
                self.methods_by_name.setdefault(lname, []).append(ms)

    # ------------------------------------------------------------ functions
    def _build_functions(self):
        self.functions = {}
        for fi in self.files.values():
            self._functions_for_file(fi)

    def _functions_for_file(self, fi):
        fkey = "file:" + fi.rel
        top = []
        self._collect(fi.stmts, fi, fi.ctx_root, None, fkey, top)
        self.functions[fkey] = FunctionRec(fkey, "file", fi.rel, None, top, [], fi, fi.ctx_root)

    def _collect(self, stmts, fi, ctx, cls, parent_key, top):
        """Split a statement list into FunctionRecs; `top` receives the statements
        that run when the enclosing unit runs (declarations are excluded)."""
        for s in stmts:
            if s is None:
                continue
            k = s.kind
            if k == "Namespace":
                self._collect(s.body, fi, s.ctx, cls, parent_key, top)
                continue
            if k == "Function":
                key = s.sym.key if getattr(s, "sym", None) else "f:" + s.name.lower()
                if key in self.functions:              # duplicate (conditional) definition
                    key = key + "@" + fi.rel + ":" + str(s.line)
                rec = FunctionRec(key, "function", s.name, s, s.body, s.params, fi, s.ctx, None, parent_key,
                                  getattr(s, "sym", None))
                self.functions[key] = rec
                self._closures(s.body, fi, s.ctx, None, key)
                continue
            if k == "Class":
                self._class_functions(s, fi, parent_key)
                continue
            top.append(s)
        self._closures(top, fi, ctx, cls, parent_key)

    def _class_functions(self, node, fi, parent_key):
        csym = getattr(node, "sym", None)
        if csym is None:
            return
        cctx = node.ctx
        for m in node.members:
            if m.kind == "Method" and m.body is not None:
                ms = m.sym
                key = ms.key
                if key in self.functions:
                    key = key + "@" + fi.rel + ":" + str(m.line)
                self.functions[key] = FunctionRec(key, "method", m.name, m, m.body, m.params, fi, cctx, csym.fq,
                                                  parent_key, ms)
                self._closures(m.body, fi, cctx, csym.fq, key)

    def _closures(self, stmts, fi, ctx, cls, parent_key):
        """Closures, arrow fns and anonymous/nested classes inside a body become their own units."""
        stack = list(stmts)
        while stack:
            n = stack.pop()
            if n is None:
                continue
            k = n.kind
            if k in ("Closure", "ArrowFn"):
                key = "c:%s:%d:%d" % (fi.rel, n.line, n.col)
                body = n.body if k == "Closure" else [Node("Return", n.line, n.col, expr=n.expr)]
                self.functions[key] = FunctionRec(key, "closure", None, n, body, n.params, fi, ctx, cls, parent_key)
                self._node_keys[id(n)] = key
                stack.extend(body)
                continue
            if k == "Class":
                if n.name is None:                       # anonymous class
                    self._anon_class(n, fi, ctx, parent_key)
                else:
                    self._class_functions(n, fi, parent_key)
                continue
            if k == "Function":
                if getattr(n, "sym", None) is not None and n.sym.key not in self.functions:
                    self.functions[n.sym.key] = FunctionRec(n.sym.key, "function", n.name, n, n.body, n.params, fi,
                                                            n.ctx, None, parent_key, n.sym)
                    self._closures(n.body, fi, n.ctx, None, n.sym.key)
                continue
            stack.extend(n.children())

    def _anon_class(self, node, fi, ctx, parent_key):
        fq = "class@anonymous@%s:%d:%d" % (fi.rel, node.line, node.col)
        node.name_fq = fq
        if fq.lower() not in self.classes:
            fake = Node("Class", node.line, node.col, **{k: v for k, v in node.__dict__.items()
                                                       if k not in ("name", "sym", "ctx")})
            fake.name = fq
            self._index_class(fake, fi, ctx)
            node.sym = fake.sym
            node.ctx = fake.ctx
            self._link_hierarchy_one(node.sym)
        self._class_functions(node, fi, parent_key)

    def _link_hierarchy_one(self, sym):
        for base in ([sym.parent] if sym.parent else []) + sym.interfaces:
            self.subclasses.setdefault(base.lower(), set()).add(sym.fq.lower())
        for lname, ms in sym.methods.items():
            self.methods_by_name.setdefault(lname, []).append(ms)

    # ---------------------------------------------------------------- query
    def resolve_class(self, name, ctx):
        """Fully-qualified class name for `name` as written in `ctx`."""
        return qualify(name, ctx, "class")

    def get_class(self, fq):
        """ClassSym for a fully-qualified name, parsing a vendor file via the
        autoload map on first use."""
        if not fq:
            return None
        low = fq.lstrip("\\").lower()
        sym = self.classes.get(low)
        if sym is not None or self.vendor_mode == "none":
            return sym
        if low in self._autoload_tried:
            return None
        self._autoload_tried.add(low)
        path = self.autoload_file(fq)
        if path and path not in self.files:
            fi = self.add_file(path)
            for n in walk(fi.stmts):
                if n.kind == "Class" and getattr(n, "sym", None) is not None:
                    self._link_hierarchy_one(n.sym)
            self._functions_for_file(fi)
        return self.classes.get(low)

    def resolve_function(self, name, ctx):
        """FuncSym for a function call `name(...)` in `ctx` (namespaced first, then global)."""
        if name.startswith("\\"):
            return self.funcs.get(name[1:].lower())
        low = name.lower()
        if "\\" not in name:
            alias = ctx.uses["function"].get(low)
            if alias:
                return self.funcs.get(alias.lower())
            if ctx.namespace:
                s = self.funcs.get((ctx.namespace + "\\" + name).lower())
                if s:
                    return s
            return self.funcs.get(low)
        return self.funcs.get(qualify(name, ctx, "function").lower())

    def ancestors(self, fq):
        """The class, its parents (nearest first). Stops on cycles."""
        ck = ("anc", fq.lower())
        hit = self._cache.get(ck)
        if hit is not None:
            return hit
        out = self._ancestors(fq)
        self._cache[ck] = out
        return out

    def _ancestors(self, fq):
        out, seen = [], set()
        cur = self.get_class(fq)
        while cur is not None and cur.fq.lower() not in seen:
            seen.add(cur.fq.lower())
            out.append(cur)
            cur = self.get_class(cur.parent) if cur.parent else None
        return out

    def method_lookup(self, fq, name, _seen=None):
        """Method `name` on class `fq`: own methods, then used traits (with
        insteadof/as adaptations), then the parent chain, then interfaces."""
        if _seen is None:
            ck = ("m", fq.lower(), name.lower())
            if ck in self._cache:
                return self._cache[ck]
            r = self._method_lookup(fq, name, set())
            self._cache[ck] = r
            return r
        return self._method_lookup(fq, name, _seen)

    def _method_lookup(self, fq, name, _seen):
        lname = name.lower()
        seen = _seen if _seen is not None else set()
        for c in self.ancestors(fq):
            key = c.fq.lower()
            if key in seen:
                continue
            seen.add(key)
            m = c.methods.get(lname)
            if m is not None:
                return m
            tm = self._trait_method(c, lname, seen)
            if tm is not None:
                return tm
        cls = self.get_class(fq)
        if cls is not None:
            for iface in cls.interfaces:
                m = self.method_lookup(iface, name, seen)
                if m is not None:
                    return m
        return None

    def _trait_method(self, cls, lname, seen):
        # aliases: "foo as bar" makes bar callable; "A::x insteadof B" picks A's x
        for ad in cls.trait_adapt:
            if ad.kind == "TraitAlias" and ad.alias and ad.alias.lower() == lname:
                src_traits = [qualify(ad.trait, cls.ctx)] if ad.trait else cls.traits
                for t in src_traits:
                    m = self.method_lookup(t, ad.method, set(seen))
                    if m is not None:
                        return m
        excluded = set()
        for ad in cls.trait_adapt:
            if ad.kind == "TraitInsteadof" and ad.method.lower() == lname:
                for o in ad.insteadof:
                    excluded.add(qualify(o, cls.ctx).lower())
        for t in cls.traits:
            if t.lower() in excluded:
                continue
            m = self.method_lookup(t, lname, set(seen))
            if m is not None:
                return m
        return None

    def implementations(self, fq, name, limit=12):
        """Concrete methods named `name` in classes below `fq` (subclasses and
        implementors), for calls on an interface or abstract type."""
        ck = ("impl", fq.lower(), name.lower(), limit)
        if ck in self._cache:
            return self._cache[ck]
        r = self._implementations(fq, name, limit)
        self._cache[ck] = r
        return r

    def _implementations(self, fq, name, limit):
        out, todo, seen = [], [fq.lower()], set()
        while todo and len(out) < limit:
            cur = todo.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for sub in self.subclasses.get(cur, ()):
                sc = self.classes.get(sub)
                if sc is None:
                    continue
                m = self.method_lookup(sc.fq, name)
                if m is not None and not m.abstract and m not in out:
                    out.append(m)
                todo.append(sub)
        return out

    def prop_types(self, fq, name):
        for c in self.ancestors(fq):
            p = c.props.get(name)
            if p is not None:
                return p.types
            if name in c.magic_props:
                return c.magic_props[name]
            for t in c.traits:
                tc = self.get_class(t)
                if tc is not None and name in tc.props:
                    return tc.props[name].types
        return []

    def const_values(self, name, fi=None):
        """Definitions of a global constant; definitions in `fi` first."""
        defs = self.constants.get(name.lstrip("\\"), [])
        if fi is not None:
            same = [d for d in defs if d[1] is fi]
            if same:
                return same
        return defs

    def function_key_for_node(self, node):
        return self._node_keys.get(id(node))

    def iter_functions(self, include_vendor=False):
        for rec in self.functions.values():
            if include_vendor or not rec.file.vendor:
                yield rec

    def file(self, path):
        return self.files.get(os.path.abspath(path))

    def stats(self):
        return {"files": len(self.files), "vendor_files": sum(1 for f in self.files.values() if f.vendor),
                "files_with_errors": sum(1 for f in self.files.values() if f.errors),
                "internal_errors": sum(1 for f in self.files.values() if f.internal_error),
                "classes": len(self.classes), "functions": len(self.funcs), "units": len(self.functions),
                "includes": len(self.includes), "truncated": self.truncated}
