"""Symbols and name resolution: namespaces, `use` imports, classes, functions,
methods, properties, constants, and docblock type hints."""
from __future__ import annotations

import re

BUILTIN_TYPES = frozenset("""int integer string bool boolean float double array callable iterable object mixed
void null never false true resource numeric scalar self static parent this $this list non-empty-string
positive-int negative-int non-empty-array class-string array-key key-of value-of""".split())


class NameCtx:
    """Name-resolution context: the namespace, `use` imports, and the enclosing class."""
    __slots__ = ("namespace", "uses", "cls", "parent", "file")

    def __init__(self, namespace="", uses=None, cls=None, parent=None, file=None):
        self.namespace = namespace or ""
        self.uses = uses if uses is not None else {"class": {}, "function": {}, "const": {}}
        self.cls = cls          # fq name of the enclosing class, or None
        self.parent = parent    # fq name of the enclosing class's parent, or None
        self.file = file

    def with_class(self, cls, parent):
        return NameCtx(self.namespace, self.uses, cls, parent, self.file)

    def copy_uses(self):
        return NameCtx(self.namespace, {k: dict(v) for k, v in self.uses.items()}, self.cls, self.parent, self.file)


def qualify(name, ctx, kind="class"):
    """Fully-qualified name (no leading backslash) per PHP resolution rules.
    For functions/constants this is the namespaced candidate; callers fall back
    to the global name when it does not exist (PHP's fallback rule)."""
    if not name:
        return name
    if name[0] == "\\":
        return name[1:]
    low = name.lower()
    if low.startswith("namespace\\"):
        rest = name[10:]
        return (ctx.namespace + "\\" + rest) if ctx.namespace else rest
    if kind == "class":
        if low in ("self", "static"):
            return ctx.cls or name
        if low == "parent":
            return ctx.parent or name
        if low in BUILTIN_TYPES:
            return low
    first, sep, rest = name.partition("\\")
    if sep:
        alias = ctx.uses["class"].get(first.lower())
        if alias:
            return alias + "\\" + rest
    else:
        table = ctx.uses["class" if kind == "class" else kind]
        alias = table.get(name.lower())
        if alias:
            return alias
    return (ctx.namespace + "\\" + name) if ctx.namespace else name


class ClassSym:
    __slots__ = ("fq", "name", "type", "parent", "interfaces", "traits", "trait_adapt", "methods", "props",
                 "consts", "file", "node", "ctx", "vendor", "abstract", "magic_props")

    def __init__(self, fq, node, ctx, file, vendor=False):
        self.fq = fq
        self.name = node.name if node is not None else fq.rsplit("\\", 1)[-1]
        self.type = node.type if node is not None else "class"
        self.parent = None
        self.interfaces = []
        self.traits = []
        self.trait_adapt = []
        self.methods = {}
        self.props = {}
        self.consts = {}
        self.file = file
        self.node = node
        self.ctx = ctx
        self.vendor = vendor
        self.abstract = node is not None and "abstract" in (node.flags or [])
        self.magic_props = {}

    def __repr__(self):
        return "ClassSym(%s)" % self.fq


class MethodSym:
    __slots__ = ("name", "cls", "node", "flags", "static", "abstract", "rtypes", "params", "key", "visibility")

    def __init__(self, name, cls, node, rtypes):
        self.name = name
        self.cls = cls
        self.node = node
        self.flags = node.flags or []
        self.static = "static" in self.flags
        self.abstract = node.body is None
        self.rtypes = rtypes
        self.params = node.params
        self.key = "m:%s::%s" % (cls.fq.lower(), name.lower())
        self.visibility = next((f for f in self.flags if f in ("public", "protected", "private")), "public")

    def __repr__(self):
        return "MethodSym(%s::%s)" % (self.cls.fq, self.name)


class FuncSym:
    __slots__ = ("fq", "name", "node", "file", "ctx", "rtypes", "key")

    def __init__(self, fq, node, file, ctx, rtypes):
        self.fq = fq
        self.name = node.name
        self.node = node
        self.file = file
        self.ctx = ctx
        self.rtypes = rtypes
        self.key = "f:" + fq.lower()

    def __repr__(self):
        return "FuncSym(%s)" % self.fq


class PropSym:
    __slots__ = ("name", "cls", "types", "static", "node")

    def __init__(self, name, cls, types, static, node):
        self.name = name
        self.cls = cls
        self.types = types
        self.static = static
        self.node = node


# ------------------------------------------------------------------ docblocks
_DOC_TAG = re.compile(r"@(param|var|return|property(?:-read|-write)?|method)\s+([^\s*]+(?:\s*\|\s*[^\s*]+)*)"
                      r"(?:\s+(&?\.{0,3}\$[A-Za-z_\x80-\xff][\w\x80-\xff]*))?")
_DOC_VAR_FIRST = re.compile(r"@var\s+(\$[A-Za-z_\x80-\xff][\w\x80-\xff]*)\s+([^\s*]+)")


def parse_doc(doc):
    """{'param': {name: type_str}, 'var': [(type_str, name|None)], 'return': type_str|None,
    'property': {name: type_str}}"""
    out = {"param": {}, "var": [], "return": None, "property": {}}
    if not doc:
        return out
    for m in _DOC_TAG.finditer(doc):
        tag, typ, var = m.group(1), m.group(2), m.group(3)
        if typ.startswith("$"):           # "@var $x Foo" order
            continue
        name = var.lstrip("&.").lstrip("$") if var else None
        if tag == "param" and name:
            out["param"][name] = typ
        elif tag == "var":
            out["var"].append((typ, name))
        elif tag == "return":
            out["return"] = typ
        elif tag.startswith("property") and name:
            out["property"][name] = typ
    for m in _DOC_VAR_FIRST.finditer(doc):
        out["var"].append((m.group(2), m.group(1)[1:]))
    return out


def type_names(typ):
    """Class-like names in a type string ('?Foo|Bar[]|array<int, Baz>' -> Foo, Bar, Baz)."""
    if not typ:
        return []
    out = []
    for part in re.split(r"[|&()<>,\s{}:]+", typ):
        part = part.strip().lstrip("?").rstrip("[]").strip()
        if not part or part.lower() in BUILTIN_TYPES or part.startswith("$") or part[0].isdigit() \
                or part[0] in "'\"-":
            continue
        if not re.match(r"^\\?[A-Za-z_\x80-\xff][\w\x80-\xff\\]*$", part):
            continue
        out.append(part)
    return out


def node_type_names(tnode):
    """Names in a parsed Type node."""
    if tnode is None:
        return []
    return [n for n in tnode.names if n.lower() not in BUILTIN_TYPES or n.lower() in ("self", "static", "parent")]
