"""Recursive-descent / Pratt parser for PHP 8.3.

    from phpwarden.sast.parser import parse
    res = parse(source_text, path="x.php")
    res.stmts      # list of statement Nodes
    res.errors     # list of ParseError (message, line, col); never raises
    res.comments   # [(line, text)]

Error recovery: a statement that cannot be parsed is recorded in `errors` and
skipped up to the next `;` or closing brace at the same depth, so one bad
construct never stops the rest of the file (or the project) from being read.
"""
from __future__ import annotations

import re
import sys
from bisect import bisect_right

from .ast import Node
from .lexer import Lexer, LexError, unescape_dq, unescape_sq


class ParseError(Exception):
    def __init__(self, msg, line=0, col=0):
        super().__init__(msg)
        self.msg = msg
        self.line = line
        self.col = col

    def __repr__(self):
        return "ParseError(%r, line=%d, col=%d)" % (self.msg, self.line, self.col)


class ParseResult:
    __slots__ = ("stmts", "errors", "comments", "path", "src", "internal_error")

    def __init__(self, stmts, errors, comments, path, src, internal_error=None):
        self.stmts = stmts
        self.errors = errors
        self.comments = comments
        self.path = path
        self.src = src
        self.internal_error = internal_error


# binding powers (higher binds tighter); see PHP's operator precedence table
_BIN = {
    "or": 1, "xor": 2, "and": 3,
    "??": 6, "||": 7, "&&": 8, "|": 9, "^": 10, "&": 11,
    "==": 12, "!=": 12, "===": 12, "!==": 12, "<>": 12, "<=>": 12,
    "<": 13, "<=": 13, ">": 13, ">=": 13,
    ".": 14, "<<": 15, ">>": 15, "+": 16, "-": 16, "*": 17, "/": 17, "%": 17,
    "instanceof": 19, "**": 21,
}
_RIGHT = frozenset(("??", "**"))
_WORD_OPS = frozenset(("or", "xor", "and", "instanceof"))
_ASSIGN = frozenset(("=", "+=", "-=", "*=", "/=", ".=", "%=", "**=", "&=", "|=", "^=", "<<=", ">>=", "??="))
_LVALUE = frozenset(("Var", "ArrayDim", "PropFetch", "StaticProp", "List", "Array"))
_P_TERNARY = 5
_P_ASSIGN = 4
_P_NOT = 18
_P_UNARY = 20

_MODIFIERS = frozenset(("public", "protected", "private", "static", "abstract", "final", "readonly", "var"))
_INCLUDES = frozenset(("include", "include_once", "require", "require_once"))
_MAGIC = frozenset(("__line__", "__file__", "__dir__", "__function__", "__class__", "__method__",
                    "__namespace__", "__trait__", "__property__", "__compiler_halt_offset__"))
_RESERVED = frozenset("""abstract and array as break callable case catch class clone const continue declare
default do echo else elseif empty enddeclare endfor endforeach endif endswitch endwhile eval exit die extends
final finally fn for foreach function global goto if implements include include_once instanceof insteadof
interface isset list match namespace new or print private protected public readonly require require_once
return static switch throw trait try unset use var while xor yield""".split())
_CALLBACK_EXPR_END = frozenset((";", ")", ",", "]", "close", "eof", "}"))


_new_node = object.__new__


class Parser:
    def __init__(self, toks, src, docs):
        self.t = toks
        self.i = 0
        self.src = src
        self.docs = docs
        self.errors = []
        nl = []
        find = src.find
        p = find("\n")
        while p != -1:
            nl.append(p)
            p = find("\n", p + 1)
        self.nl = nl

    # ------------------------------------------------------------ positions
    def lc(self, off):
        ln = bisect_right(self.nl, off - 1) if off > 0 else 0
        start = self.nl[ln - 1] + 1 if ln > 0 else 0
        return ln + 1, off - start + 1

    def node(self, kind, off, **f):
        # inlined lc() and Node(): called once per AST node, the parser's hot path
        nl = self.nl
        ln = bisect_right(nl, off - 1) if off > 0 else 0
        n = _new_node(Node)
        n.kind = kind
        n.line = ln + 1
        n.col = off - (nl[ln - 1] + 1 if ln > 0 else 0) + 1
        if f:
            n.__dict__.update(f)
        return n

    # --------------------------------------------------------------- tokens
    def peek(self, k=0):
        j = self.i + k
        t = self.t
        return t[j] if j < len(t) else t[-1]

    def next(self):
        tok = self.t[self.i]
        if tok[0] != "eof":
            self.i += 1
        return tok

    def is_(self, typ):
        return self.t[self.i][0] == typ

    def kw(self, word, k=0):
        tok = self.peek(k)
        return tok[0] == "id" and tok[1].lower() == word

    def accept(self, typ):
        if self.t[self.i][0] == typ:
            return self.next()
        return None

    def accept_kw(self, word):
        if self.kw(word):
            return self.next()
        return None

    def error(self, msg, tok=None):
        tok = tok or self.peek()
        ln, col = self.lc(tok[2])
        return ParseError(msg, ln, col)

    def expect(self, typ, what=None):
        tok = self.t[self.i]
        if tok[0] != typ:
            raise self.error("expected %s, found %s" % (what or repr(typ), _desc(tok)))
        return self.next()

    def expect_kw(self, word):
        if not self.kw(word):
            raise self.error("expected '%s', found %s" % (word, _desc(self.peek())))
        return self.next()

    def end_stmt(self):
        typ = self.t[self.i][0]
        if typ == ";":
            self.i += 1
        elif typ == "close":
            self.i += 1
        elif typ == "eof":
            pass
        else:
            raise self.error("expected ';', found %s" % _desc(self.t[self.i]))

    def ident(self, what="identifier"):
        """Any identifier, including reserved words (method/const/property names)."""
        tok = self.t[self.i]
        if tok[0] != "id":
            raise self.error("expected %s, found %s" % (what, _desc(tok)))
        self.i += 1
        return tok[1]

    def doc_at(self, off):
        return self.docs.get(off)

    # ----------------------------------------------------------- statements
    def parse_file(self):
        stmts = []
        while not self.is_("eof"):
            self.parse_top(stmts)
        return stmts

    def parse_top(self, out):
        if self.kw("namespace") and not self.peek(1)[0] == "\\" and self.peek(1)[0] != "(":
            start = self.i
            try:
                out.append(self.parse_namespace())
            except ParseError as e:
                self.errors.append(e)
                self.recover(start)
            return
        s = self.stmt_safe()
        if s is not None:
            out.append(s)

    def stmt_safe(self):
        start = self.i
        try:
            r = self.parse_stmt()
            if r is not None and "doc" not in r.__dict__:
                d = self.docs.get(self.t[start][2])
                if d is not None:
                    r.doc = d
            return r
        except ParseError as e:
            self.errors.append(e)
            self.recover(start)
            return None
        except RecursionError:
            self.errors.append(self.error("nesting too deep"))
            self.recover(start)
            return None

    def recover(self, start):
        t = self.t
        if self.i == start and t[self.i][0] != "eof":
            self.i += 1
        depth = 0
        while True:
            typ = t[self.i][0]
            if typ == "eof":
                return
            if typ in ("{", "(", "["):
                depth += 1
            elif typ in ("}", ")", "]"):
                if depth == 0:
                    return
                depth -= 1
                if depth == 0 and typ == "}":
                    self.i += 1
                    return
            elif (typ == ";" or typ == "close") and depth == 0:
                self.i += 1
                return
            self.i += 1

    def block_until(self, *enders):
        """Statements until one of the closing keywords/tokens (not consumed)."""
        out = []
        while True:
            tok = self.t[self.i]
            if tok[0] == "eof":
                return out
            if tok[0] in enders or (tok[0] == "id" and tok[1].lower() in enders):
                return out
            s = self.stmt_safe()
            if s is not None:
                out.append(s)

    def braced_block(self):
        self.expect("{")
        out = self.block_until("}")
        self.expect("}")
        return out

    def parse_namespace(self):
        tok = self.next()
        name = None
        if self.is_("id"):
            name = self.next()[1]
        if self.accept("{"):
            body = self.block_until("}")
            self.expect("}")
            return self.node("Namespace", tok[2], name=name, body=body, braced=True)
        self.end_stmt()
        body = []
        while not self.is_("eof"):
            if self.kw("namespace") and self.peek(1)[0] not in ("\\", "("):
                break
            s = self.stmt_safe()
            if s is not None:
                body.append(s)
        return self.node("Namespace", tok[2], name=name, body=body, braced=False)

    def parse_stmt(self):
        tok = self.t[self.i]
        typ = tok[0]
        if typ == "html":
            self.i += 1
            return self.node("InlineHTML", tok[2], text=tok[1])
        if typ == "open_echo":
            self.i += 1
            exprs = self.expr_list_until((";", "close", "eof"))
            self.end_stmt()
            return self.node("Echo", tok[2], exprs=exprs, short=True)
        if typ == ";" or typ == "close":
            self.i += 1
            return None
        if typ == "{":
            self.i += 1
            body = self.block_until("}")
            self.expect("}")
            return self.node("Block", tok[2], body=body)
        if typ == "#[":
            attrs = self.attributes()
            return self.decl_after_attrs(attrs, tok)
        if typ == "id":
            w = tok[1].lower()
            nxt = self.peek(1)[0]
            if nxt == ":" and w not in _RESERVED and w not in ("default", "else", "case"):
                self.i += 2
                return self.node("Label", tok[2], name=tok[1])
            h = _STMT_KW.get(w)
            if h is not None:
                r = h(self, tok)
                if r is not _EXPR:
                    return r
        e = self.expr()
        self.end_stmt()
        return self.node("ExprStmt", tok[2], expr=e)

    # each handler returns a Node, or _EXPR to fall back to an expression statement
    def s_if(self, tok):
        self.next()
        self.expect("(")
        cond = self.expr()
        self.expect(")")
        if self.accept(":"):
            body = self.block_until("elseif", "else", "endif")
            elifs, else_ = [], None
            while True:
                if self.kw("elseif"):
                    t2 = self.next()
                    self.expect("(")
                    c2 = self.expr()
                    self.expect(")")
                    self.expect(":")
                    b2 = self.block_until("elseif", "else", "endif")
                    elifs.append(self.node("ElseIf", t2[2], cond=c2, body=b2))
                elif self.kw("else"):
                    self.next()
                    if self.kw("if"):           # "else if" inside alternative syntax
                        else_ = [self.parse_stmt()]
                        continue
                    self.expect(":")
                    else_ = self.block_until("endif")
                else:
                    break
            self.expect_kw("endif")
            self.end_stmt()
            return self.node("If", tok[2], cond=cond, body=body, elifs=elifs, else_=else_, alt=True)
        body = self.stmt_as_list()
        elifs, else_ = [], None
        while True:
            if self.kw("elseif"):
                t2 = self.next()
                self.expect("(")
                c2 = self.expr()
                self.expect(")")
                b2 = self.stmt_as_list()
                elifs.append(self.node("ElseIf", t2[2], cond=c2, body=b2))
            elif self.kw("else"):
                self.next()
                else_ = self.stmt_as_list()
                break
            else:
                break
        return self.node("If", tok[2], cond=cond, body=body, elifs=elifs, else_=else_, alt=False)

    def stmt_as_list(self):
        s = self.parse_stmt()
        if s is None:
            return []
        if s.kind == "Block":
            return s.body
        return [s]

    def s_while(self, tok):
        self.next()
        self.expect("(")
        cond = self.expr()
        self.expect(")")
        if self.accept(":"):
            body = self.block_until("endwhile")
            self.expect_kw("endwhile")
            self.end_stmt()
        else:
            body = self.stmt_as_list()
        return self.node("While", tok[2], cond=cond, body=body)

    def s_do(self, tok):
        self.next()
        body = self.stmt_as_list()
        self.expect_kw("while")
        self.expect("(")
        cond = self.expr()
        self.expect(")")
        self.end_stmt()
        return self.node("DoWhile", tok[2], cond=cond, body=body)

    def s_for(self, tok):
        self.next()
        self.expect("(")
        init = self.expr_list_until((";",))
        self.expect(";")
        cond = self.expr_list_until((";",))
        self.expect(";")
        step = self.expr_list_until((")",))
        self.expect(")")
        if self.accept(":"):
            body = self.block_until("endfor")
            self.expect_kw("endfor")
            self.end_stmt()
        else:
            body = self.stmt_as_list()
        return self.node("For", tok[2], init=init, cond=cond, step=step, body=body)

    def s_foreach(self, tok):
        self.next()
        self.expect("(")
        subject = self.expr()
        self.expect_kw("as")
        key = None
        byref = bool(self.accept("&"))
        value = self.expr()
        if self.accept("=>"):
            key = value
            byref = bool(self.accept("&"))
            value = self.expr()
        self.expect(")")
        if value.kind in ("Array", "List"):
            _to_list(value)
        if self.accept(":"):
            body = self.block_until("endforeach")
            self.expect_kw("endforeach")
            self.end_stmt()
        else:
            body = self.stmt_as_list()
        return self.node("Foreach", tok[2], subject=subject, key=key, value=value, byref=byref, body=body)

    def s_switch(self, tok):
        self.next()
        self.expect("(")
        cond = self.expr()
        self.expect(")")
        alt = False
        if self.accept(":"):
            alt = True
        else:
            self.expect("{")
        cases = []
        while True:
            while self.is_("html") or self.is_(";") or self.is_("close"):
                self.next()
            if alt and self.kw("endswitch"):
                self.next()
                self.end_stmt()
                break
            if not alt and self.accept("}"):
                break
            if self.is_("eof"):
                raise self.error("unterminated switch")
            if self.kw("case"):
                ct = self.next()
                test = self.expr()
                if not self.accept(":") and not self.accept(";"):
                    raise self.error("expected ':' after case")
            elif self.kw("default"):
                ct = self.next()
                test = None
                if not self.accept(":") and not self.accept(";"):
                    raise self.error("expected ':' after default")
            else:
                raise self.error("expected case or default, found %s" % _desc(self.peek()))
            body = self.block_until("case", "default", "}", "endswitch")
            cases.append(self.node("Case", ct[2], test=test, body=body))
        return self.node("Switch", tok[2], cond=cond, cases=cases)

    def s_break(self, tok):
        self.next()
        lv = None
        if not self.is_(";") and not self.is_("close") and not self.is_("eof"):
            lv = self.expr()
        self.end_stmt()
        return self.node("Break" if tok[1].lower() == "break" else "Continue", tok[2], levels=lv)

    def s_return(self, tok):
        self.next()
        e = None
        if not self.is_(";") and not self.is_("close") and not self.is_("eof"):
            e = self.expr()
        self.end_stmt()
        return self.node("Return", tok[2], expr=e)

    def s_global(self, tok):
        self.next()
        names = [self.expr(_P_UNARY)]
        while self.accept(","):
            names.append(self.expr(_P_UNARY))
        self.end_stmt()
        return self.node("Global", tok[2], vars=names)

    def s_static(self, tok):
        if self.peek(1)[0] != "var":
            return _EXPR
        self.next()
        items = []
        while True:
            vt = self.expect("var")
            default = None
            if self.accept("="):
                default = self.expr()
            items.append(self.node("StaticVar", vt[2], name=vt[1], default=default))
            if not self.accept(","):
                break
        self.end_stmt()
        return self.node("Static", tok[2], vars=items)

    def s_echo(self, tok):
        self.next()
        exprs = self.expr_list_until((";", "close", "eof"))
        self.end_stmt()
        return self.node("Echo", tok[2], exprs=exprs, short=False)

    def s_unset(self, tok):
        if self.peek(1)[0] != "(":
            return _EXPR
        self.next()
        self.expect("(")
        items = self.expr_list_until((")",))
        self.expect(")")
        self.end_stmt()
        return self.node("Unset", tok[2], vars=items)

    def s_try(self, tok):
        self.next()
        body = self.braced_block()
        catches, fin = [], None
        while self.kw("catch"):
            ct = self.next()
            self.expect("(")
            types = [self.expect("id")[1]]
            while self.accept("|"):
                types.append(self.expect("id")[1])
            var = None
            if self.is_("var"):
                var = self.next()[1]
            self.expect(")")
            cb = self.braced_block()
            catches.append(self.node("Catch", ct[2], types=types, var=var, body=cb))
        if self.kw("finally"):
            self.next()
            fin = self.braced_block()
        return self.node("Try", tok[2], body=body, catches=catches, finally_=fin)

    def s_goto(self, tok):
        self.next()
        name = self.ident()
        self.end_stmt()
        return self.node("Goto", tok[2], label=name)

    def s_declare(self, tok):
        self.next()
        self.expect("(")
        directives = []
        while not self.is_(")"):
            k = self.ident()
            self.expect("=")
            directives.append(self.node("Directive", tok[2], name=k, value=self.expr()))
            if not self.accept(","):
                break
        self.expect(")")
        body = None
        if self.accept(":"):
            body = self.block_until("enddeclare")
            self.expect_kw("enddeclare")
            self.end_stmt()
        elif self.is_(";") or self.is_("close"):
            self.end_stmt()
        else:
            body = self.stmt_as_list()
        return self.node("Declare", tok[2], directives=directives, body=body)

    def s_use(self, tok):
        self.next()
        kind = "class"
        if self.kw("function") or self.kw("const"):
            kind = self.next()[1].lower()
        uses = []
        while True:
            nt = self.expect("id", "name")
            name = nt[1].lstrip("\\")
            if self.is_("\\") and self.peek(1)[0] == "{":
                self.next()
                self.next()
                while not self.is_("}"):
                    k2 = kind
                    if self.kw("function") or self.kw("const"):
                        k2 = self.next()[1].lower()
                    st = self.expect("id", "name")
                    alias = None
                    if self.accept_kw("as"):
                        alias = self.ident()
                    uses.append(self.node("UseItem", st[2], name=name + "\\" + st[1].lstrip("\\"),
                                          alias=alias, type=k2))
                    if not self.accept(","):
                        break
                self.expect("}")
            elif name.endswith("\\") is False and self.peek()[0] == "{":
                raise self.error("bad group use")
            else:
                alias = None
                if self.accept_kw("as"):
                    alias = self.ident()
                uses.append(self.node("UseItem", nt[2], name=name, alias=alias, type=kind))
            if not self.accept(","):
                break
        self.end_stmt()
        return self.node("Use", tok[2], uses=uses)

    def s_const(self, tok):
        self.next()
        items = []
        while True:
            nt = self.expect("id")
            self.expect("=")
            items.append(self.node("ConstItem", nt[2], name=nt[1], value=self.expr()))
            if not self.accept(","):
                break
        self.end_stmt()
        return self.node("Const", tok[2], consts=items)

    def s_function(self, tok):
        j = 1
        if self.peek(1)[0] == "&":
            j = 2
        if self.peek(j)[0] != "id":
            return _EXPR                    # closure expression statement
        return self.function_decl(tok, [])

    def s_namespace(self, tok):
        if self.peek(1)[0] in ("\\", "("):
            return _EXPR
        return self.parse_namespace()

    def s_class_like(self, tok):
        w = tok[1].lower()
        if w == "enum":
            p1 = self.peek(1)
            if p1[0] != "id" or self.peek(2)[0] not in ("{", ":") and not (
                    self.peek(2)[0] == "id" and self.peek(2)[1].lower() == "implements"):
                return _EXPR
        if w in ("abstract", "final", "readonly"):
            # modifiers must be followed (eventually) by "class"
            j = 1
            while self.peek(j)[0] == "id" and self.peek(j)[1].lower() in ("abstract", "final", "readonly"):
                j += 1
            if not self.kw("class", j):
                return _EXPR
        return self.class_decl([], tok)

    def s_halt(self, tok):
        self.next()
        self.accept("(")
        self.accept(")")
        if self.is_(";") or self.is_("close"):
            self.next()
        self.i = len(self.t) - 1
        return self.node("HaltCompiler", tok[2])

    def decl_after_attrs(self, attrs, tok):
        if self.kw("function") or (self.kw("fn")) or self.kw("static"):
            if self.kw("function"):
                j = 2 if self.peek(1)[0] == "&" else 1
                if self.peek(j)[0] == "id":
                    return self.function_decl(self.peek(), attrs)
            e = self.expr()
            self.end_stmt()
            return self.node("ExprStmt", tok[2], expr=e)
        if self.is_("id") and self.peek()[1].lower() in ("abstract", "final", "readonly", "class",
                                                         "interface", "trait", "enum"):
            return self.class_decl(attrs, self.peek())
        raise self.error("attribute not followed by a declaration")

    # ---------------------------------------------------------- declarations
    def attributes(self):
        out = []
        while self.is_("#["):
            st = self.next()
            while not self.is_("]"):
                nt = self.expect("id", "attribute name")
                args = self.args() if self.is_("(") else []
                out.append(self.node("Attribute", nt[2], name=nt[1], args=args))
                if not self.accept(","):
                    break
            self.expect("]")
        return out

    def function_decl(self, tok, attrs):
        start_off = tok[2]
        doc = self.doc_at(start_off)
        self.expect_kw("function")
        byref = bool(self.accept("&"))
        name = self.ident("function name")
        params = self.params()
        rtype = self.return_type()
        body = self.braced_block()
        return self.node("Function", start_off, name=name, params=params, byref=byref,
                         rtype=rtype, body=body, attrs=attrs, doc=doc)

    def return_type(self):
        if self.accept(":"):
            return self.type_()
        return None

    def params(self):
        self.expect("(")
        out = []
        while not self.is_(")"):
            st = self.peek()
            attrs = self.attributes() if self.is_("#[") else []
            flags = []
            while self.is_("id") and self.peek()[1].lower() in ("public", "protected", "private", "readonly"):
                flags.append(self.modifier())
            ptype = None
            if not self.is_("var") and not self.is_("&") and not self.is_("..."):
                ptype = self.type_()
            byref = bool(self.accept("&"))
            variadic = bool(self.accept("..."))
            vt = self.expect("var", "parameter")
            default = None
            if self.accept("="):
                default = self.expr()
            out.append(self.node("Param", vt[2], name=vt[1], type=ptype, byref=byref, variadic=variadic,
                                 default=default, flags=flags, attrs=attrs, doc=self.doc_at(st[2])))
            if not self.accept(","):
                break
        self.expect(")")
        return out

    def type_(self):
        st = self.peek()
        nullable = bool(self.accept("?"))
        names = []
        text = []

        def atom():
            if self.accept("("):
                inner = [self.expect("id")[1]]
                while self.accept("&"):
                    inner.append(self.expect("id")[1])
                self.expect(")")
                names.extend(inner)
                text.append("(" + "&".join(inner) + ")")
                return
            t = self.expect("id", "type")
            names.append(t[1])
            text.append(t[1])

        atom()
        while True:
            if self.is_("|"):
                self.next()
                text.append("|")
                atom()
            elif self.is_("&") and self.peek(1)[0] not in ("var", "...", "&") and \
                    not (self.peek(1)[0] == "&"):
                self.next()
                text.append("&")
                atom()
            else:
                break
        return self.node("Type", st[2], names=names, nullable=nullable,
                         text=("?" if nullable else "") + "".join(text))

    def class_decl(self, attrs, tok):
        start_off = tok[2]
        doc = self.doc_at(start_off)
        flags = []
        while self.is_("id") and self.peek()[1].lower() in ("abstract", "final", "readonly"):
            flags.append(self.next()[1].lower())
        kt = self.expect("id")
        kind = kt[1].lower()
        if kind not in ("class", "interface", "trait", "enum"):
            raise self.error("expected class declaration", kt)
        name = self.ident("class name")
        parent = None
        interfaces = []
        backing = None
        if kind == "enum" and self.accept(":"):
            backing = self.type_()
        if self.accept_kw("extends"):
            if kind == "interface":
                interfaces.append(self.expect("id")[1])
                while self.accept(","):
                    interfaces.append(self.expect("id")[1])
            else:
                parent = self.expect("id")[1]
        if self.accept_kw("implements"):
            interfaces.append(self.expect("id")[1])
            while self.accept(","):
                interfaces.append(self.expect("id")[1])
        members = self.class_body()
        return self.node("Class", start_off, type=kind, name=name, parent=parent, interfaces=interfaces,
                         flags=flags, members=members, attrs=attrs, doc=doc, backing=backing)

    def class_body(self):
        self.expect("{")
        members = []
        while not self.is_("}"):
            if self.is_("eof"):
                raise self.error("unterminated class body")
            start = self.i
            try:
                m = self.member()
                if m is not None:
                    members.append(m)
            except ParseError as e:
                self.errors.append(e)
                self.recover(start)
        self.expect("}")
        return members

    def member(self):
        st = self.peek()
        attrs = self.attributes() if self.is_("#[") else []
        st2 = self.peek()
        doc = self.doc_at(st[2]) or self.doc_at(st2[2])
        if self.accept(";"):
            return None
        if self.kw("use"):
            return self.trait_use()
        if self.kw("case"):
            ct = self.next()
            name = self.ident()
            val = None
            if self.accept("="):
                val = self.expr()
            self.end_stmt()
            return self.node("EnumCase", ct[2], name=name, value=val, attrs=attrs, doc=doc)
        flags = []
        while self.is_("id") and self.peek()[1].lower() in _MODIFIERS and not (
                self.peek()[1].lower() == "static" and self.peek(1)[0] == "::"):
            flags.append(self.modifier())
        if self.kw("const"):
            ct = self.next()
            ctype = None
            # typed constant (8.3): const string NAME = ...
            if not (self.is_("id") and self.peek(1)[0] == "="):
                ctype = self.type_()
            items = []
            while True:
                nt = self.expect("id")
                self.expect("=")
                items.append(self.node("ConstItem", nt[2], name=nt[1], value=self.expr()))
                if not self.accept(","):
                    break
            self.end_stmt()
            return self.node("ClassConst", ct[2], consts=items, flags=flags, type=ctype, attrs=attrs, doc=doc)
        if self.kw("function"):
            ft = self.next()
            byref = bool(self.accept("&"))
            name = self.ident("method name")
            params = self.params()
            rtype = self.return_type()
            body = None
            if self.is_("{"):
                body = self.braced_block()
            else:
                self.end_stmt()
            return self.node("Method", ft[2], name=name, params=params, flags=flags, byref=byref,
                             rtype=rtype, body=body, attrs=attrs, doc=doc)
        ptype = None
        if not self.is_("var"):
            ptype = self.type_()
        props = []
        first = self.peek()
        while True:
            vt = self.expect("var", "property")
            default = None
            if self.accept("="):
                default = self.expr()
            # property hooks (8.4) are not PHP 8.3; skip a hook block if present
            props.append(self.node("PropItem", vt[2], name=vt[1], default=default))
            if not self.accept(","):
                break
        if self.is_("{"):
            self.braced_skip()
        else:
            self.end_stmt()
        return self.node("Property", first[2], props=props, flags=flags, type=ptype, attrs=attrs, doc=doc)

    def modifier(self):
        """A member modifier; `private(set)` style asymmetric visibility (8.4) is
        returned as "private(set)"."""
        m = self.next()[1].lower()
        if m in ("public", "protected", "private") and self.is_("(") and self.kw("set", 1) \
                and self.peek(2)[0] == ")":
            self.i += 3
            return m + "(set)"
        return m

    def braced_skip(self):
        depth = 0
        while not self.is_("eof"):
            t = self.next()[0]
            if t == "{":
                depth += 1
            elif t == "}":
                depth -= 1
                if depth == 0:
                    return

    def trait_use(self):
        ut = self.next()
        traits = [self.expect("id")[1]]
        while self.accept(","):
            traits.append(self.expect("id")[1])
        adaptations = []
        if self.accept("{"):
            while not self.is_("}"):
                at = self.peek()
                cls = None
                meth = self.ident()
                if self.accept("::"):
                    cls, meth = meth, self.ident()
                if self.accept_kw("insteadof"):
                    others = [self.expect("id")[1]]
                    while self.accept(","):
                        others.append(self.expect("id")[1])
                    adaptations.append(self.node("TraitInsteadof", at[2], trait=cls, method=meth,
                                                 insteadof=others))
                else:
                    self.expect_kw("as")
                    vis = None
                    alias = None
                    if self.is_("id") and self.peek()[1].lower() in ("public", "protected", "private"):
                        vis = self.next()[1].lower()
                    if self.is_("id"):
                        alias = self.next()[1]
                    adaptations.append(self.node("TraitAlias", at[2], trait=cls, method=meth,
                                                 visibility=vis, alias=alias))
                self.end_stmt()
            self.expect("}")
        else:
            self.end_stmt()
        return self.node("TraitUse", ut[2], traits=traits, adaptations=adaptations)

    # ----------------------------------------------------------- expressions
    def expr_list_until(self, enders):
        out = []
        if self.t[self.i][0] in enders:
            return out
        while True:
            out.append(self.expr())
            if not self.accept(","):
                break
            if self.t[self.i][0] in enders:      # trailing comma
                break
        return out

    def expr(self, min_bp=0):
        left = self.prefix()
        t = self.t
        while True:
            tok = t[self.i]
            typ = tok[0]
            if typ == "id":
                w = tok[1].lower()
                if w not in _WORD_OPS:
                    return left
                op = w
            else:
                op = typ
            if op in _ASSIGN:
                if left.kind not in _LVALUE:
                    return left
                self.i += 1
                if op == "=" and t[self.i][0] == "&":
                    self.i += 1
                    value = self.expr(_P_ASSIGN)
                    left = Node("AssignRef", left.line, left.col, target=left, value=value)
                else:
                    if left.kind == "Array":
                        _to_list(left)
                    value = self.expr(_P_ASSIGN)
                    left = Node("Assign", left.line, left.col, op=op, target=left, value=value)
                continue
            if op == "?":
                if _P_TERNARY < min_bp:
                    return left
                self.i += 1
                if self.accept(":"):
                    then = None
                else:
                    then = self.expr(_P_ASSIGN)
                    self.expect(":")
                else_ = self.expr(_P_TERNARY + 1)
                left = Node("Ternary", left.line, left.col, cond=left, then=then, else_=else_)
                continue
            bp = _BIN.get(op)
            if bp is None or bp < min_bp:
                return left
            self.i += 1
            if op == "instanceof":
                right = self.expr(_P_UNARY)
                left = Node("Instanceof", left.line, left.col, expr=left, cls=right)
                continue
            right = self.expr(bp if op in _RIGHT else bp + 1)
            left = Node("BinOp", left.line, left.col, op=op, left=left, right=right)

    def prefix(self):
        tok = self.t[self.i]
        typ = tok[0]
        off = tok[2]
        if typ == "var":
            self.i += 1
            return self.postfix(self.node("Var", off, name=tok[1]))
        if typ == "id":
            return self.prefix_id(tok)
        if typ == "num":
            self.i += 1
            v = tok[1].replace("_", "")
            low = v.lower()
            if low.startswith("0x") or low.startswith("0b") or low.startswith("0o") or \
                    ("." not in v and "e" not in low):
                return self.postfix(self.node("Int", off, value=v))
            return self.postfix(self.node("Float", off, value=v))
        if typ == "str":
            self.i += 1
            return self.postfix(self.node("String", off, value=unescape_sq(tok[1]), raw=tok[1], quote="'"))
        if typ == "dq" or typ == "heredoc":
            self.i += 1
            return self.postfix(self.interp(tok))
        if typ == "bt":
            self.i += 1
            return self.node("ShellExec", off, parts=self.interp_parts(tok[1]))
        if typ == "cast":
            self.i += 1
            return self.node("Cast", off, type=tok[1], expr=self.expr(_P_UNARY))
        if typ == "(":
            self.i += 1
            e = self.expr()
            self.expect(")")
            e.paren = True
            return self.postfix(e)
        if typ == "[":
            return self.postfix(self.array_lit("]"))
        if typ == "!":
            self.i += 1
            return self.node("UnaryOp", off, op="!", expr=self.expr(_P_NOT))
        if typ in ("-", "+", "~", "@"):
            self.i += 1
            return self.node("UnaryOp", off, op=typ, expr=self.expr(_P_UNARY))
        if typ == "&":                     # &$x in odd positions (e.g. array_walk(&$x))
            self.i += 1
            return self.node("Ref", off, expr=self.expr(_P_UNARY))
        if typ == "++" or typ == "--":
            self.i += 1
            return self.node("IncDec", off, op=typ, prefix=True, var=self.expr(_P_UNARY))
        if typ == "$":
            return self.postfix(self.var_var())
        if typ == "#[":
            self.attributes()
            return self.prefix()
        if typ == "\\":
            raise self.error("unexpected '\\'")
        raise self.error("unexpected %s" % _desc(tok))

    def var_var(self):
        st = self.next()             # "$"
        if self.accept("{"):
            e = self.expr()
            self.expect("}")
            return self.node("Var", st[2], name=e)
        if self.is_("$"):
            return self.node("Var", st[2], name=self.var_var())
        vt = self.expect("var", "variable")
        return self.node("Var", st[2], name=self.node("Var", vt[2], name=vt[1]))

    def prefix_id(self, tok):
        w = tok[1].lower()
        off = tok[2]
        nxt = self.peek(1)[0]
        h = _EXPR_KW.get(w)
        if h is not None:
            r = h(self, tok, nxt)
            if r is not None:
                return r
        self.i += 1
        if w in _MAGIC:
            return self.postfix(self.node("MagicConst", off, name=w))
        return self.postfix(self.node("Name", off, name=tok[1]))

    # keyword-led expressions; return None to treat the word as a plain name
    def e_new(self, tok, nxt):
        self.i += 1
        off = tok[2]
        if self.is_("#["):
            self.attributes()
        if self.kw("class"):
            ct = self.next()
            args = self.args() if self.is_("(") else []
            parent = None
            ifaces = []
            if self.accept_kw("extends"):
                parent = self.expect("id")[1]
            if self.accept_kw("implements"):
                ifaces.append(self.expect("id")[1])
                while self.accept(","):
                    ifaces.append(self.expect("id")[1])
            members = self.class_body()
            cls = self.node("Class", ct[2], type="class", name=None, parent=parent, interfaces=ifaces,
                            flags=[], members=members, attrs=[], doc=None, backing=None)
            return self.postfix(self.node("New", off, cls=cls, args=args))
        if self.is_("id"):
            nt = self.next()
            cls = self.node("Name", nt[2], name=nt[1])
        elif self.is_("("):
            self.next()
            cls = self.expr()
            self.expect(")")
        else:
            cls = self.class_ref()
        args = self.args() if self.is_("(") else []
        return self.postfix(self.node("New", off, cls=cls, args=args))

    def class_ref(self):
        """Dynamic class reference after `new`: a variable with property / static /
        array access, but no calls (new $a->b() calls the class named by $a->b)."""
        if self.is_("$"):
            e = self.var_var()
        else:
            vt = self.expect("var", "class name")
            e = self.node("Var", vt[2], name=vt[1])
        while True:
            if self.is_("[") :
                self.next()
                dim = None if self.is_("]") else self.expr()
                self.expect("]")
                e = Node("ArrayDim", e.line, e.col, var=e, dim=dim)
            elif self.is_("->") or self.is_("?->"):
                op = self.next()[0]
                name = self.member_name()
                e = Node("PropFetch", e.line, e.col, obj=e, name=name, nullsafe=op == "?->")
            elif self.is_("::") and self.peek(1)[0] == "var":
                self.next()
                vt = self.next()
                e = Node("StaticProp", e.line, e.col, cls=e, name=vt[1])
            else:
                return e

    def e_clone(self, tok, nxt):
        self.i += 1
        return self.node("Clone", tok[2], expr=self.expr(_P_UNARY + 2))

    def e_closure(self, tok, nxt):
        w = tok[1].lower()
        off = tok[2]
        static = False
        if w == "static":
            if not (self.kw("function", 1) or self.kw("fn", 1)):
                return None
            self.i += 1
            static = True
            w = self.peek()[1].lower()
        self.i += 1
        byref = bool(self.accept("&"))
        if w == "fn":
            params = self.params()
            rtype = self.return_type()
            self.expect("=>")
            body = self.expr(_P_ASSIGN)
            return self.node("ArrowFn", off, params=params, byref=byref, static=static, rtype=rtype,
                             expr=body)
        params = self.params()
        uses = []
        if self.accept_kw("use"):
            self.expect("(")
            while not self.is_(")"):
                r = bool(self.accept("&"))
                vt = self.expect("var")
                uses.append(self.node("ClosureUse", vt[2], name=vt[1], byref=r))
                if not self.accept(","):
                    break
            self.expect(")")
        rtype = self.return_type()
        body = self.braced_block()
        return self.postfix(self.node("Closure", off, params=params, uses=uses, byref=byref, static=static,
                                      rtype=rtype, body=body))

    def e_fn(self, tok, nxt):
        if nxt not in ("(", "&"):
            return None
        return self.e_closure(tok, nxt)

    def e_function(self, tok, nxt):
        if nxt not in ("(", "&"):
            return None
        return self.e_closure(tok, nxt)

    def e_static(self, tok, nxt):
        if self.kw("function", 1) or self.kw("fn", 1):
            return self.e_closure(tok, nxt)
        return None

    def e_isset(self, tok, nxt):
        if nxt != "(":
            return None
        self.i += 1
        self.expect("(")
        items = self.expr_list_until((")",))
        self.expect(")")
        return self.node("Isset", tok[2], vars=items)

    def e_empty(self, tok, nxt):
        if nxt != "(":
            return None
        self.i += 1
        self.expect("(")
        e = self.expr()
        self.expect(")")
        return self.node("Empty", tok[2], expr=e)

    def e_exit(self, tok, nxt):
        self.i += 1
        e = None
        if self.accept("("):
            if not self.is_(")"):
                e = self.expr()
            self.expect(")")
        return self.node("Exit", tok[2], expr=e, word=tok[1].lower())

    def e_print(self, tok, nxt):
        self.i += 1
        return self.node("Print", tok[2], expr=self.expr(_P_ASSIGN))

    def e_include(self, tok, nxt):
        self.i += 1
        return self.node("Include", tok[2], type=tok[1].lower(), expr=self.expr(_P_ASSIGN))

    def e_eval(self, tok, nxt):
        if nxt != "(":
            return None
        self.i += 1
        self.expect("(")
        e = self.expr()
        self.expect(")")
        return self.node("Eval", tok[2], expr=e)

    def e_array(self, tok, nxt):
        if nxt != "(":
            return None
        self.i += 1
        return self.postfix(self.array_lit(")", tok))

    def e_list(self, tok, nxt):
        if nxt != "(":
            return None
        self.i += 1
        a = self.array_lit(")", tok)
        a.kind = "List"
        return a

    def e_match(self, tok, nxt):
        if nxt != "(":
            return None
        self.i += 1
        self.expect("(")
        subject = self.expr()
        self.expect(")")
        self.expect("{")
        arms = []
        while not self.is_("}"):
            at = self.peek()
            conds = None
            if self.kw("default") and self.peek(1)[0] in ("=>", ","):
                self.next()
                self.accept(",")
            else:
                conds = [self.expr()]
                while self.accept(","):
                    if self.is_("=>"):
                        break
                    conds.append(self.expr())
            self.expect("=>")
            body = self.expr()
            arms.append(self.node("MatchArm", at[2], conds=conds, body=body))
            if not self.accept(","):
                break
        self.expect("}")
        return self.postfix(self.node("Match", tok[2], subject=subject, arms=arms))

    def e_throw(self, tok, nxt):
        self.i += 1
        return self.node("Throw", tok[2], expr=self.expr(0))

    def e_yield(self, tok, nxt):
        self.i += 1
        off = tok[2]
        if self.kw("from"):
            self.next()
            return self.node("YieldFrom", off, expr=self.expr(_P_ASSIGN))
        if self.t[self.i][0] in _CALLBACK_EXPR_END:
            return self.node("Yield", off, key=None, value=None)
        v = self.expr(_P_ASSIGN)
        if self.accept("=>"):
            return self.node("Yield", off, key=v, value=self.expr(_P_ASSIGN))
        return self.node("Yield", off, key=None, value=v)

    def array_lit(self, closer, tok=None):
        st = tok or self.peek()
        if tok is None:
            self.expect("[")
        else:
            self.expect("(")
        items = []
        while not self.is_(closer):
            if self.is_(","):          # skipped slot in list()
                it = self.next()
                items.append(None)
                continue
            it = self.peek()
            if self.accept("..."):
                items.append(self.node("ArrayItem", it[2], key=None, value=self.expr(), byref=False, unpack=True))
            elif self.accept("&"):
                items.append(self.node("ArrayItem", it[2], key=None, value=self.expr(), byref=True, unpack=False))
            else:
                v = self.expr()
                if self.accept("=>"):
                    r = bool(self.accept("&"))
                    items.append(self.node("ArrayItem", it[2], key=v, value=self.expr(), byref=r, unpack=False))
                else:
                    items.append(self.node("ArrayItem", it[2], key=None, value=v, byref=False, unpack=False))
            if not self.accept(","):
                break
        self.expect(closer)
        return self.node("Array", st[2], items=[x for x in items if x is not None],
                         holes=sum(1 for x in items if x is None), short=tok is None)

    def member_name(self):
        """Name after -> or ?-> : identifier (incl. reserved words), $var or {expr}."""
        tok = self.t[self.i]
        if tok[0] == "id":
            self.i += 1
            return tok[1]
        if tok[0] == "var":
            self.i += 1
            return self.node("Var", tok[2], name=tok[1])
        if tok[0] == "{":
            self.i += 1
            e = self.expr()
            self.expect("}")
            return e
        if tok[0] == "$":
            return self.var_var()
        raise self.error("expected member name, found %s" % _desc(tok))

    def postfix(self, e):
        t = self.t
        while True:
            typ = t[self.i][0]
            if typ == "[":
                self.i += 1
                dim = None if t[self.i][0] == "]" else self.expr()
                self.expect("]")
                e = Node("ArrayDim", e.line, e.col, var=e, dim=dim)
            elif typ == "->" or typ == "?->":
                self.i += 1
                name = self.member_name()
                if t[self.i][0] == "(":
                    args, fcc = self.args_fcc()
                    e = Node("MethodCall", e.line, e.col, obj=e, name=name, args=args, nullsafe=typ == "?->",
                             callable=fcc)
                else:
                    e = Node("PropFetch", e.line, e.col, obj=e, name=name, nullsafe=typ == "?->")
            elif typ == "::":
                self.i += 1
                tok = t[self.i]
                if tok[0] == "var":
                    self.i += 1
                    if t[self.i][0] == "(":
                        args, fcc = self.args_fcc()
                        e = Node("StaticCall", e.line, e.col, cls=e,
                                 name=self.node("Var", tok[2], name=tok[1]), args=args, callable=fcc)
                    else:
                        e = Node("StaticProp", e.line, e.col, cls=e, name=tok[1])
                elif tok[0] == "id":
                    self.i += 1
                    if t[self.i][0] == "(":
                        args, fcc = self.args_fcc()
                        e = Node("StaticCall", e.line, e.col, cls=e, name=tok[1], args=args, callable=fcc)
                    else:
                        e = Node("ClassConst", e.line, e.col, cls=e, name=tok[1])
                elif tok[0] == "{":
                    self.i += 1
                    nm = self.expr()
                    self.expect("}")
                    args, fcc = self.args_fcc()
                    e = Node("StaticCall", e.line, e.col, cls=e, name=nm, args=args, callable=fcc)
                elif tok[0] == "$":
                    vv = self.var_var()
                    e = Node("StaticProp", e.line, e.col, cls=e, name=vv)
                else:
                    raise self.error("unexpected %s after ::" % _desc(tok))
            elif typ == "(":
                args, fcc = self.args_fcc()
                e = Node("Call", e.line, e.col, func=e, args=args, callable=fcc)
            elif (typ == "++" or typ == "--") and e.kind in _LVALUE:
                self.i += 1
                e = Node("IncDec", e.line, e.col, op=typ, prefix=False, var=e)
            else:
                return e

    def args(self):
        a, _ = self.args_fcc()
        return a

    def args_fcc(self):
        self.expect("(")
        if self.is_("...") and self.peek(1)[0] == ")":
            self.next()
            self.next()
            return [], True
        out = []
        while not self.is_(")"):
            at = self.peek()
            name = None
            if at[0] == "id" and self.peek(1)[0] == ":" and self.peek(2)[0] != ":":
                name = at[1]
                self.i += 2
            unpack = bool(self.accept("..."))
            v = self.expr()
            out.append(self.node("Arg", at[2], value=v, name=name, unpack=unpack))
            if not self.accept(","):
                break
        self.expect(")")
        return out, False

    # ------------------------------------------------------------- strings
    def interp_parts(self, parts):
        out = []
        for p in parts:
            if p[0] == "lit":
                out.append(self.node("String", p[2], value=unescape_dq(p[1]), raw=p[1], quote='"'))
            else:
                sub = Parser(list(p[1]) + [("eof", "", p[2])], self.src, self.docs)
                sub.nl = self.nl
                try:
                    e = sub.expr()
                    if not sub.is_("eof"):
                        raise sub.error("unexpected token in string interpolation")
                except ParseError as err:
                    self.errors.append(err)
                    e = self.node("String", p[2], value="", raw="", quote='"')
                self.errors.extend(sub.errors)
                out.append(e)
        return out

    def interp(self, tok):
        parts = tok[1]
        kind = "heredoc" if tok[0] == "heredoc" else "double"
        if all(p[0] == "lit" for p in parts):
            raw = "".join(p[1] for p in parts)
            return self.node("String", tok[2], value=unescape_dq(raw), raw=raw, quote=kind)
        return self.node("Interp", tok[2], parts=self.interp_parts(parts), quote=kind)


def _to_list(node):
    """An array literal used as an assignment target is a destructuring list,
    and so are array literals nested in it."""
    node.kind = "List"
    for it in node.items:
        if it.value is not None and it.value.kind in ("Array", "List"):
            _to_list(it.value)


def _desc(tok):
    typ = tok[0]
    if typ == "eof":
        return "end of file"
    if typ in ("id", "var", "num"):
        return "%s %r" % (typ, tok[1] if typ != "var" else "$" + tok[1])
    if typ in ("str", "dq", "heredoc", "bt"):
        return "string"
    return repr(typ)


_EXPR = object()

_STMT_KW = {
    "if": Parser.s_if, "while": Parser.s_while, "do": Parser.s_do, "for": Parser.s_for,
    "foreach": Parser.s_foreach, "switch": Parser.s_switch, "break": Parser.s_break,
    "continue": Parser.s_break, "return": Parser.s_return, "global": Parser.s_global,
    "static": Parser.s_static, "echo": Parser.s_echo, "unset": Parser.s_unset, "try": Parser.s_try,
    "goto": Parser.s_goto, "declare": Parser.s_declare, "use": Parser.s_use, "const": Parser.s_const,
    "function": Parser.s_function, "namespace": Parser.s_namespace,
    "class": Parser.s_class_like, "interface": Parser.s_class_like, "trait": Parser.s_class_like,
    "enum": Parser.s_class_like, "abstract": Parser.s_class_like, "final": Parser.s_class_like,
    "readonly": Parser.s_class_like, "__halt_compiler": Parser.s_halt,
}

_EXPR_KW = {
    "new": Parser.e_new, "clone": Parser.e_clone, "function": Parser.e_function, "fn": Parser.e_fn,
    "static": Parser.e_static, "isset": Parser.e_isset, "empty": Parser.e_empty,
    "exit": Parser.e_exit, "die": Parser.e_exit, "print": Parser.e_print,
    "include": Parser.e_include, "include_once": Parser.e_include, "require": Parser.e_include,
    "require_once": Parser.e_include, "eval": Parser.e_eval, "array": Parser.e_array,
    "list": Parser.e_list, "match": Parser.e_match, "throw": Parser.e_throw, "yield": Parser.e_yield,
}


def parse(src, path="<string>"):
    """Parse PHP source. Never raises: errors are returned in the result.
    `src` may be str (ideally decoded as latin-1) or bytes."""
    if isinstance(src, bytes):
        src = src.decode("latin-1")
    lx = Lexer(src)
    errors = []
    try:
        toks = lx.tokenize()
    except LexError as e:
        # keep what was lexed so far; the parser recovers from the cut
        toks = None
        p = Parser([("eof", "", 0)], src, {})
        ln, col = p.lc(e.off)
        errors.append(ParseError("lex: " + str(e), ln, col))
        # re-lex the prefix before the error so declarations before it are kept
        try:
            lx2 = Lexer(src[:e.off])
            toks = lx2.tokenize()
            lx = lx2
        except LexError:
            toks = [("eof", "", 0)]
    old = sys.getrecursionlimit()
    if old < 20000:
        sys.setrecursionlimit(20000)
    p = Parser(toks, src, lx.docs)
    internal = None
    stmts = []
    try:
        stmts = p.parse_file()
    except RecursionError:
        p.errors.append(ParseError("nesting too deep", 0, 0))
    except Exception as e:  # noqa: BLE001 — never crash on a file; recorded and counted
        internal = "%s: %s" % (e.__class__.__name__, e)
        p.errors.append(ParseError("internal parser error: " + internal, 0, 0))
    comments = [(p.lc(off)[0], text) for off, text in lx.comments]
    return ParseResult(stmts, errors + p.errors, comments, path, src, internal)


# A PHP file with no variables, no declarations, no includes and no output
# (after removing strings and comments) is a data table, e.g. a translation or
# emoji map returned as an array literal. It declares no symbols and can carry
# no request data, so the analysis does not need its syntax tree.
_STRIP = re.compile(r"(?s)'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|/\*.*?\*/|//[^\n]*|#[^\n]*")
_ACTIVE = re.compile(r"\b(?:function|class|interface|trait|enum|fn|include|require|include_once|require_once"
                     r"|define|new|echo|print|eval|exit|die|namespace|use|const|static|global)\b|[$`]|<<<|\?>", re.I)
DATA_ONLY_MIN = 4096          # small files are cheap to parse anyway


def is_data_only(src):
    return len(src) >= DATA_ONLY_MIN and not _ACTIVE.search(_STRIP.sub("", src))


def parse_file(path):
    with open(path, "rb") as fh:
        data = fh.read()
    src = data.decode("latin-1")
    if is_data_only(src):
        return ParseResult([], [], [], path, src)
    return parse(src, path)
