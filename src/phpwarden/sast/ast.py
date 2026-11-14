"""AST node type for the phpwarden SAST parser.

Every node is a `Node` with a `kind` string (e.g. "Call", "Assign", "Class"),
a 1-based `line` and `col`, and kind-specific fields set as attributes. The
field names per kind are listed in README.md. Children are Nodes or lists of
Nodes; `children()` and `walk()` iterate them generically, so later layers can
traverse without knowing every kind.
"""
from __future__ import annotations

_SKIP = frozenset(("kind", "line", "col", "doc", "parent", "sym"))


class Node:
    __slots__ = ("kind", "line", "col", "__dict__")

    def __init__(self, kind, line=0, col=0, **fields):
        self.kind = kind
        self.line = line
        self.col = col
        if fields:
            self.__dict__.update(fields)

    def get(self, name, default=None):
        return self.__dict__.get(name, default)

    def fields(self):
        return {k: v for k, v in self.__dict__.items() if k not in _SKIP}

    def children(self):
        for k, v in self.__dict__.items():
            if k in _SKIP:
                continue
            if isinstance(v, Node):
                yield v
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, Node):
                        yield x

    def __repr__(self):
        f = ", ".join("%s=%r" % (k, v) for k, v in self.fields().items()
                      if not isinstance(v, (list, Node)))
        return "%s@%d:%d(%s)" % (self.kind, self.line, self.col, f)


def walk(node):
    """Depth-first, pre-order iteration over `node` (a Node or list of Nodes)."""
    stack = list(reversed(node)) if isinstance(node, list) else [node]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        yield n
        kids = list(n.children())
        kids.reverse()
        stack.extend(kids)


def find(node, kind):
    """All descendants (incl. node) of the given kind or kinds."""
    kinds = (kind,) if isinstance(kind, str) else tuple(kind)
    return [n for n in walk(node) if n.kind in kinds]


def dump(node, indent=0):
    """Readable multi-line dump, for debugging and tests."""
    pad = "  " * indent
    if isinstance(node, list):
        return "\n".join(dump(x, indent) for x in node)
    if not isinstance(node, Node):
        return pad + repr(node)
    out = [pad + repr(node)]
    for k, v in node.fields().items():
        if isinstance(v, Node):
            out.append(pad + "  ." + k + ":")
            out.append(dump(v, indent + 2))
        elif isinstance(v, list) and any(isinstance(x, Node) for x in v):
            out.append(pad + "  ." + k + "[]:")
            out.append(dump([x for x in v if isinstance(x, Node)], indent + 2))
    return "\n".join(out)
