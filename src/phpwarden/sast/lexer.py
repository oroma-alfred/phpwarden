"""PHP 8.3 lexer.

Produces a flat list of tokens `(type, value, offset)`:

  html        inline HTML outside <?php ... ?>          value: the text
  open_echo   "<?="                                       (acts like `echo`)
  close       "?>"                                        (acts like `;`)
  var         $name                                       value: name without "$"
  id          identifier or qualified name (Foo\\Bar, \\Foo, namespace\\X)
  num         numeric literal                             value: source text
  str         single-quoted string                        value: raw incl. quotes
  dq          double-quoted string                        value: parts (see below)
  bt          backtick shell string                       value: parts
  heredoc     heredoc / nowdoc                            value: parts
  cast        (int) (string) ...                          value: lower-cased type
  #[          attribute start
  <op>        every operator / punctuation; type == value (e.g. "->", "??=", "(")
  eof

Interpolated strings carry `parts`: a list of ("lit", raw_text, offset) and
("expr", [tokens], offset). Expression parts are already tokenised, with
offsets into the same source, so the parser parses them like any other code.

Source is expected to be decoded as latin-1 (one char per byte), which makes
offsets byte offsets and identifier rules match PHP exactly.

Comments are collected in `Lexer.comments` as (offset, text); a docblock
(/** ... */) is remembered in `Lexer.docs` keyed by the offset of the next
token, so declarations can pick up their @param/@var/@return hints.
"""
from __future__ import annotations

import re

_ID = r"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*"
_IDRX = re.compile(_ID)
_IDSTART = re.compile(r"[A-Za-z_\x80-\xff]")

_OPS = sorted("""
<<= >>= **= ... <=> === !== ??= ?->
<< >> ** ++ -- += -= *= /= .= %= &= |= ^= == != <> <= >= && || ?? -> => ::
#[
; : , . [ ] ( ) { } + - * / % = < > ! ? & | ^ ~ @ $ \\
""".split(), key=len, reverse=True)

_PHP = re.compile(
    r"(?P<ws>[ \t\r\n\f\v]+)"
    r"|(?P<lc>(?://|\#(?!\[))(?:[^\r\n?]|\?(?!>))*)"
    r"|(?P<doc>/\*\*(?=[\s*])(?:.*?)\*/)"
    r"|(?P<bc>/\*.*?\*/)"
    r"|(?P<close>\?>(?:\r\n|\n)?)"
    r"|(?P<var>\$" + _ID + r")"
    r"|(?P<num>0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|0[bB][01](?:_?[01])*|0[oO][0-7](?:_?[0-7])*"
    r"|(?:\d(?:_?\d)*)?\.\d(?:_?\d)*(?:[eE][+-]?\d(?:_?\d)*)?"
    r"|\d(?:_?\d)*(?:\.(?!\.)(?:\d(?:_?\d)*)?)?(?:[eE][+-]?\d(?:_?\d)*)?)"
    r"|(?P<id>\\?" + _ID + r"(?:\\" + _ID + r")*)"
    r"|(?P<sq>'(?:[^'\\]|\\.)*')"
    r"|(?P<cast>\([ \t]*(?i:int|integer|bool|boolean|float|double|real|string|binary|array|object|unset)[ \t]*\))"
    r"|(?P<heredoc><<<[ \t]*(?:\"(?P<hq>" + _ID + r")\"|'(?P<nq>" + _ID + r")'|(?P<hb>" + _ID + r"))\r?\n)"
    r"|(?P<op>" + "|".join(re.escape(o) for o in _OPS) + r")",
    re.S)

_OPEN = re.compile(r"<\?php(?=[\s]|$)\s?|<\?=|<\?(?=\s)", re.I)
_DQ = re.compile(r'[\\"$]|\{\$')
_BT = re.compile(r"[\\`$]|\{\$")
_HD = re.compile(r"[\\$]|\{\$")
_VAR = re.compile(r"\$(" + _ID + ")")
_OFFSET = re.compile(r"(-?\d+)|(" + _ID + r")|\$(" + _ID + ")")


class LexError(Exception):
    def __init__(self, msg, off):
        super().__init__(msg)
        self.off = off


class Lexer:
    def __init__(self, src: str):
        self.src = src
        self.n = len(src)
        self.comments = []
        self.docs = {}
        self._pending_doc = None
        self._halt = 0

    # ------------------------------------------------------------------ api
    def tokenize(self):
        toks = []
        i = self._html(0, toks)
        try:
            self._php(i, toks, None)
        except LexError:
            toks.append(("eof", "", self.n))
            raise
        toks.append(("eof", "", self.n))
        return toks

    # ---------------------------------------------------------------- modes
    def _html(self, i, toks):
        src = self.src
        m = _OPEN.search(src, i)
        if not m:
            if i < self.n:
                toks.append(("html", src[i:], i))
            return self.n
        if m.start() > i:
            toks.append(("html", src[i:m.start()], i))
        if m.group().startswith("<?="):
            toks.append(("open_echo", "<?=", m.start()))
        return m.end()

    def _emit(self, toks, tok):
        toks.append(tok)
        if self._pending_doc is not None:
            self.docs[tok[2]] = self._pending_doc
            self._pending_doc = None

    def _php(self, i, toks, brace):
        """Lex PHP code from i. brace=None: until EOF (top level).
        brace=0: inside a "{$...}" interpolation; return after its closing brace."""
        src = self.src
        n = self.n
        depth = 0
        match = _PHP.match
        while i < n:
            c = src[i]
            if c == '"':
                parts, j = self._interp(i + 1, '"', None)
                self._emit(toks, ("dq", parts, i))
                i = j
                continue
            if c == "`":
                parts, j = self._interp(i + 1, "`", None)
                self._emit(toks, ("bt", parts, i))
                i = j
                continue
            m = match(src, i)
            if m is None:
                raise LexError("unexpected character %r" % c, i)
            kind = m.lastgroup
            j = m.end()
            if kind == "ws":
                i = j
                continue
            if kind == "lc" or kind == "bc":
                self.comments.append((i, m.group()))
                i = j
                continue
            if kind == "doc":
                self.comments.append((i, m.group()))
                self._pending_doc = m.group()
                i = j
                continue
            if kind == "close":
                if brace is not None:
                    raise LexError("?> inside string interpolation", i)
                self._emit(toks, ("close", "?>", i))
                if self._halt >= 3:
                    return n
                i = self._html(j, toks)
                continue
            if kind == "hb" or kind == "hq" or kind == "nq" or kind == "heredoc":
                i = self._heredoc(m, toks)
                continue
            if kind == "op":
                v = m.group()
                if brace is not None:
                    if v == "{":
                        depth += 1
                    elif v == "}":
                        if depth == 0:
                            return j
                        depth -= 1
                self._emit(toks, (v, v, i))
                if self._halt:
                    self._halt += 1 if v in "();" else 0
                    if self._halt == 4:
                        return n
            elif kind == "id":
                v = m.group()
                self._emit(toks, ("id", v, i))
                if brace is None and v.lower() == "__halt_compiler":
                    self._halt = 1
            elif kind == "var":
                self._emit(toks, ("var", m.group()[1:], i))
            elif kind == "num":
                self._emit(toks, ("num", m.group(), i))
            elif kind == "sq":
                self._emit(toks, ("str", m.group(), i))
            elif kind == "cast":
                self._emit(toks, ("cast", m.group()[1:-1].strip().lower(), i))
            i = j
        if brace is not None:
            raise LexError("unterminated {$ interpolation", i)
        return i

    # --------------------------------------------------------- interpolation
    def _interp(self, i, term, end):
        """Scan an interpolated string body from i. term: '"', '`', or None for a
        heredoc body ending at `end`. Returns (parts, position after the string)."""
        src = self.src
        parts = []
        lit = i
        rx = _DQ if term == '"' else (_BT if term == "`" else _HD)
        limit = end if end is not None else self.n
        while True:
            m = rx.search(src, i, limit)
            if m is None:
                if term is None:
                    if limit > lit:
                        parts.append(("lit", src[lit:limit], lit))
                    return parts, limit
                raise LexError("unterminated string", i - 1)
            j = m.start()
            g = m.group()
            if g == "\\":
                i = j + 2
                continue
            if g == term:
                if j > lit:
                    parts.append(("lit", src[lit:j], lit))
                return parts, j + 1
            if j > lit and g != "$":
                parts.append(("lit", src[lit:j], lit))
            if g == "{$":
                sub = []
                i = self._php(j + 1, sub, 0)
                parts.append(("expr", sub, j))
                lit = i
                continue
            # g == "$"
            k = j + 1
            if k < limit and _IDSTART.match(src, k):
                if j > lit:
                    parts.append(("lit", src[lit:j], lit))
                sub, i = self._simple_var(j, limit)
                parts.append(("expr", sub, j))
                lit = i
                continue
            if k < limit and src[k] == "{":
                if j > lit:
                    parts.append(("lit", src[lit:j], lit))
                sub = []
                i = self._php(k + 1, sub, 0)
                if sub and sub[0][0] == "id" and (len(sub) == 1 or sub[1][0] == "["):
                    sub = [("var", sub[0][1], sub[0][2])] + sub[1:]
                else:
                    sub = [("$", "$", j), ("{", "{", k)] + sub + [("}", "}", i - 1)]
                parts.append(("expr", sub, j))
                lit = i
                continue
            i = k          # a lone "$" is literal

    def _simple_var(self, j, limit):
        src = self.src
        m = _VAR.match(src, j)
        toks = [("var", m.group(1), j)]
        i = m.end()
        if i < limit and src[i] == "[":
            k = i + 1
            m2 = _OFFSET.match(src, k)
            if m2 and src.startswith("]", m2.end()):
                toks.append(("[", "[", i))
                if m2.group(1) is not None:
                    g = m2.group(1)
                    if g.startswith("-"):
                        toks.append(("-", "-", k))
                        toks.append(("num", g[1:], k + 1))
                    else:
                        toks.append(("num", g, k))
                elif m2.group(2) is not None:
                    toks.append(("str", "'" + m2.group(2) + "'", k))
                else:
                    toks.append(("var", m2.group(3), k))
                toks.append(("]", "]", m2.end()))
                i = m2.end() + 1
        elif src.startswith("->", i) or src.startswith("?->", i):
            op = "->" if src.startswith("->", i) else "?->"
            k = i + len(op)
            m2 = _IDRX.match(src, k)
            if m2 and m2.end() <= limit:
                toks.append((op, op, i))
                toks.append(("id", m2.group(), k))
                i = m2.end()
        return toks, i

    def _heredoc(self, m, toks):
        src = self.src
        start = m.start()
        label = m.group("hq") or m.group("nq") or m.group("hb")
        nowdoc = m.group("nq") is not None
        body = m.end()
        rx = re.compile(r"^([ \t]*)" + re.escape(label) + r"(?![A-Za-z0-9_\x80-\xff])", re.M)
        mm = rx.search(src, body)
        if mm is None:
            raise LexError("unterminated heredoc", start)
        end = mm.start()
        # the newline before the closing marker is not part of the string
        if end > body and src[end - 1] == "\n":
            end -= 1
            if end > body and src[end - 1] == "\r":
                end -= 1
        indent = mm.group(1)
        if nowdoc:
            parts = [("lit", src[body:end], body)] if end > body else []
        else:
            parts, _ = self._interp(body, None, end)
        if indent:
            ded = []
            for p in parts:
                if p[0] == "lit":
                    t = p[1].replace("\n" + indent, "\n")
                    if p[2] == body and t.startswith(indent):
                        t = t[len(indent):]
                    ded.append(("lit", t, p[2]))
                else:
                    ded.append(p)
            parts = ded
        self._emit(toks, ("heredoc", parts, start))
        return mm.end()


def tokenize(src: str):
    """Convenience wrapper: (tokens, comments, docs)."""
    lx = Lexer(src)
    toks = lx.tokenize()
    return toks, lx.comments, lx.docs


_ESC = re.compile(r"\\(?:([nrtvef\\$\"])|([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u\{([0-9A-Fa-f]+)\})")
_ESC_MAP = {"n": "\n", "r": "\r", "t": "\t", "v": "\v", "e": "\x1b", "f": "\f", "\\": "\\", "$": "$", '"': '"'}


def unescape_dq(raw: str) -> str:
    def rep(m):
        if m.group(1):
            return _ESC_MAP[m.group(1)]
        if m.group(2):
            return chr(int(m.group(2), 8) & 0xFF)
        if m.group(3):
            return chr(int(m.group(3), 16))
        try:
            return chr(int(m.group(4), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return _ESC.sub(rep, raw)


def unescape_sq(raw: str) -> str:
    """raw includes the surrounding quotes."""
    body = raw[1:-1]
    if "\\" not in body:
        return body
    return re.sub(r"\\([\\'])", r"\1", body)
