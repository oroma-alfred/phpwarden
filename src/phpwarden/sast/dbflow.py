"""Second-order taint through the database, and run-time callbacks.

Mixed into the taint walker. Writes of request data to a literal table.column
(raw SQL INSERT/UPDATE, $wpdb->insert/update, Eloquent create/update/fill and
attribute assignment, DB::table('t')->insert/update, Doctrine setters followed
by persist, WordPress post/comment inserts) are recorded in the first pass as
eng.stored[("db", table, column)] = (file, line, kinds, raw). In the second
pass reads of the same table.column (SELECT + fetched rows, Eloquent models,
DB::table()->first()/value(), Doctrine getters) are sources carrying the kinds
the written value had. Dynamic table or column names: nothing.

Callbacks: values passed to array_map / array_filter / usort / call_user_func /
preg_replace_callback / iterator_apply / apply_filters reach the callback's
parameters, and its return flows back where PHP returns it.
"""
from __future__ import annotations

import re

EMPTY = {}


def t_union(a, b):
    from .taint import t_union as _u
    return _u(a, b)

_QUERY_FNS = {"mysqli_query": 1, "mysql_query": 0, "mysqli_real_query": 1, "mysqli_multi_query": 1,
              "pg_query": -1, "sqlite_query": -1, "mysql_db_query": 1, "mysqli_prepare": 1, "pg_prepare": -1}
_QUERY_METHODS = frozenset({"query", "exec", "prepare", "real_query", "multi_query", "get_results", "get_row",
                            "get_col", "get_var", "executequery", "executestatement", "select", "statement",
                            "unprepared", "insert", "update", "raw"})
_FETCH_FNS = {"mysqli_fetch_row": "pos", "mysqli_fetch_array": "both", "mysqli_fetch_assoc": "name",
              "mysqli_fetch_object": "name", "mysqli_fetch_all": "rows", "mysql_fetch_row": "pos",
              "mysql_fetch_array": "both", "mysql_fetch_assoc": "name", "mysql_fetch_object": "name",
              "mysql_result": "cell", "mysqli_result": "cell", "pg_fetch_row": "pos", "pg_fetch_assoc": "name",
              "pg_fetch_array": "both", "pg_fetch_object": "name", "pg_fetch_all": "rows"}
_FETCH_METHODS = {"fetch": "both", "fetch_assoc": "name", "fetch_row": "pos", "fetch_array": "both",
                  "fetch_object": "name", "fetchobject": "name", "fetchall": "rows", "fetch_all": "rows",
                  "fetchassociative": "name", "fetchallassociative": "rows", "fetchnumeric": "pos",
                  "get_result": "same", "execute": "same", "first": "name", "get": "rows",
                  "firstorfail": "name", "sole": "name", "all": "rows", "paginate": "rows", "find": "name",
                  "findorfail": "name", "fetchone": "cell", "fetchcolumn": "cell"}
_WP_ROW_METHODS = {"get_results": "rows", "get_row": "name", "get_col": "cell", "get_var": "cell"}
_ELOQ_READS = frozenset({"find", "findorfail", "first", "firstorfail", "get", "all", "paginate", "sole",
                         "findmany", "firstwhere", "latest", "oldest", "where", "orderby", "with", "query",
                         "wherein", "take", "limit", "simplepaginate", "cursor", "lazy"})
_ELOQ_TERMINAL = frozenset({"find", "findorfail", "first", "firstorfail", "get", "all", "paginate", "sole",
                            "findmany", "firstwhere", "simplepaginate", "cursor", "lazy"})
_ELOQ_WRITES_STATIC = frozenset({"create", "forcecreate", "insert", "updateorcreate", "firstorcreate", "make"})
_ELOQ_WRITES_INST = frozenset({"update", "fill", "forcefill", "create", "insert", "updateorinsert"})
_WP_INSERTS = {"wp_insert_post": ("posts", 0), "wp_update_post": ("posts", 0),
               "wp_insert_comment": ("comments", 0), "wp_new_comment": ("comments", 0),
               "wp_update_comment": ("comments", 0), "add_comment": ("comments", 0)}
_WP_GETTERS = {"get_post": "posts", "get_comment": "comments", "get_posts": "posts", "get_comments": "comments",
               "get_page": "posts", "get_page_by_path": "posts", "get_page_by_title": "posts"}

# callback position, positions whose values reach the callback's parameters,
# and what the call returns: "cb" (the callback's return), "data" (the input),
# "both", or None
_CALLBACKS = {
    "array_map": (0, "rest", "cb"),
    "array_filter": (1, [0], "data"),
    "array_reduce": (1, [2, 0], "cb"),
    "usort": (1, [0, 0], None), "uasort": (1, [0, 0], None), "uksort": (1, [0, 0], None),
    "array_walk": (1, [0, 2], None), "array_walk_recursive": (1, [0, 2], None),
    "call_user_func": (0, "rest", "cb"),
    "call_user_func_array": (0, "spread1", "cb"),
    "forward_static_call": (0, "rest", "cb"),
    "forward_static_call_array": (0, "spread1", "cb"),
    "preg_replace_callback": (1, [2], "both"),
    "iterator_apply": (1, "spread2", None),
    "register_shutdown_function": (0, "rest", None),
}


def norm_table(t):
    t = t.strip().strip("`\"'[]").lower()
    if "." in t:
        t = t.rsplit(".", 1)[1].strip("`\"'[]")
    for pre in ("wp_",):
        if t.startswith(pre):
            t = t[len(pre):]
    return t if re.fullmatch(r"[a-z_][a-z0-9_]*", t or "") else None


def plural(name):
    s = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    if s.endswith("y") and not s.endswith(("ay", "ey", "oy", "uy")):
        return s[:-1] + "ies"
    if s.endswith(("s", "x", "ch", "sh")):
        return s + "es"
    return s + "s"


_PH = "\x00%d\x00"
_PH_RX = re.compile(r"\x00(\d+)\x00")


def _split_top(s):
    out, depth, q, cur = [], 0, None, ""
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in "'\"`":
            q = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        cur += ch
    out.append(cur)
    return [x.strip() for x in out]


def parse_write(sql):
    """-> (table, {column: value_text}) for INSERT/REPLACE ... VALUES and UPDATE ... SET."""
    m = re.search(r"\b(?:insert|replace)\s+(?:ignore\s+)?into\s+([`\"\w.]+)\s*\(([^)]*)\)\s*values?\s*\((.*)\)",
                  sql, re.I | re.S)
    if m:
        t = norm_table(m.group(1))
        cols = [c.strip().strip("`\"") .lower() for c in m.group(2).split(",")]
        vals = _split_top(m.group(3))
        if t and len(cols) == len(vals) and all(re.fullmatch(r"\w+", c) for c in cols):
            return t, dict(zip(cols, vals))
        return None
    m = re.search(r"\bupdate\s+([`\"\w.]+)\s+set\s+(.*?)(?:\swhere\s|\slimit\s|$)", sql, re.I | re.S)
    if m:
        t = norm_table(m.group(1))
        out = {}
        for asg in _split_top(m.group(2)):
            mm = re.match(r"[`\"]?(\w+)[`\"]?\s*=\s*(.*)$", asg, re.S)
            if mm:
                out[mm.group(1).lower()] = mm.group(2)
        return (t, out) if t and out else None
    return None


def parse_select(sql):
    """-> (table, [columns or '*'] in select order, {alias: column})."""
    m = re.search(r"\bselect\s+(?:distinct\s+)?(.*?)\s+from\s+([`\"\w.]+)", sql, re.I | re.S)
    if not m or _PH_RX.search(m.group(2)):
        return None
    t = norm_table(m.group(2))
    if not t:
        return None
    cols = []
    for c in _split_top(m.group(1)):
        mm = re.match(r"^(?:[`\"]?\w+[`\"]?\.)?[`\"]?(\w+|\*)[`\"]?(?:\s+(?:as\s+)?[`\"]?(\w+)[`\"]?)?$", c, re.I)
        if not mm:
            cols.append((None, None))
            continue
        cols.append((mm.group(1).lower(), (mm.group(2) or mm.group(1)).lower()))
    return t, cols


class DbFlowMixin:
    # --------------------------------------------------------- bookkeeping
    def _df_init(self):
        self.strvals = {}      # var -> list of string part nodes (query being built)
        self.dbvars = {}       # var -> ("rows"|"row", table, cols)
        self.callables = {}    # var -> callable expression
        self._setters = {}     # var -> [(prop, taint)] Doctrine setters before persist

    def _df_assign(self, name, value, env, tenv):
        k = value.kind
        if k in ("String", "Interp") or (k == "BinOp" and value.op == "."):
            parts = []
            if k == "Interp":
                parts = list(value.parts)
            elif k == "BinOp":
                self._flatten(value, parts)
            else:
                parts = [value]
            self.strvals[name] = parts
        else:
            self.strvals.pop(name, None)
        if k in ("Closure", "ArrowFn") or (k == "String" and re.fullmatch(r"[\w\\:]+", value.value or "")) \
                or (k in ("Call", "MethodCall", "StaticCall") and value.get("callable")) \
                or (k == "Array" and len(value.items or []) == 2):
            self.callables[name] = value
        else:
            self.callables.pop(name, None)
        shape = self._db_shape(value, tenv)
        if shape is not None:
            self.dbvars[name] = shape
        else:
            self.dbvars.pop(name, None)
        self._setters.pop(name, None)

    def _df_append(self, name, value):
        if name in self.strvals:
            parts = []
            if value.kind == "Interp":
                parts = list(value.parts)
            elif value.kind == "BinOp" and value.op == ".":
                self._flatten(value, parts)
            else:
                parts = [value]
            self.strvals[name] = self.strvals[name] + parts

    def _df_foreach(self, s):
        subj = s.subject
        shape = None
        if subj.kind == "Var" and isinstance(subj.name, str):
            shape = self.dbvars.get(subj.name)
        else:
            shape = self._db_shape(subj, None)
        if shape is not None and s.value is not None and s.value.kind == "Var" and isinstance(s.value.name, str):
            self.dbvars[s.value.name] = ("row", shape[1], shape[2])

    # ------------------------------------------------------- query strings
    def _sql_parts(self, e, depth=0):
        if e is None or depth > 3:
            return None
        if e.kind == "Var" and isinstance(e.name, str):
            parts = self.strvals.get(e.name)
            if parts is None:
                return [e]
            out = []
            for p in parts:
                if p.kind == "Var" and p.name in self.strvals and depth < 3:
                    out.extend(self._sql_parts(p, depth + 1) or [p])
                else:
                    out.append(p)
            return out
        if e.kind == "Interp":
            return list(e.parts)
        if e.kind == "BinOp" and e.op == ".":
            parts = []
            self._flatten(e, parts)
            out = []
            for p in parts:
                out.extend(self._sql_parts(p, depth + 1) if p.kind == "Var" and p.name in self.strvals else [p])
            return out
        if e.kind == "String":
            return [e]
        if e.kind == "Call" and e.func.kind == "Name" and e.func.name.lower() == "sprintf" and e.args:
            fmt = e.args[0].value
            if fmt.kind == "String":
                bits = re.split(r"(%(?:\d+\$)?[-+ 0']*\d*(?:\.\d+)?[sdfuxXbc])", fmt.value or "")
                out, i = [], 1
                for b in bits:
                    if b.startswith("%") and len(b) > 1 and b != "%%":
                        if i < len(e.args):
                            out.append(e.args[i].value)
                        i += 1
                    elif b:
                        out.append(_Lit(b))
                return out
        return None

    def _sql_text(self, e, env, tenv):
        """Query text with every non-literal part replaced by a placeholder, and the
        taint of each placeholder. {$wpdb->prefix} / $table_prefix dissolve."""
        parts = self._sql_parts(e)
        if not parts:
            return None, []
        text, taints = "", []
        for p in parts:
            if p.kind == "String" or isinstance(p, _Lit):
                text += p.value or ""
                continue
            if p.kind == "PropFetch" and isinstance(p.name, str) and p.name in ("prefix", "base_prefix"):
                continue
            if p.kind == "Var" and p.name in ("table_prefix", "prefix"):
                continue
            taints.append(self.expr_quiet(p, env, tenv))
            text += _PH % (len(taints) - 1)
        return text, taints

    # ----------------------------------------------------------- writes
    def _db_record(self, table, col, t, node, sanitised_xss=False):
        if not table or not col or not t:
            return
        kinds = frozenset()
        for o, v in t.items():
            if isinstance(o, int):
                kinds |= v
        kinds = kinds - {"mass"}
        if sanitised_xss:
            kinds = kinds - {"xss"}
        if not kinds:
            return
        raw = "sql" in kinds and "xss" in kinds
        kinds = (kinds - {"sqlq"}) | ({"sql"} if "sqlq" in kinds else frozenset())
        key = ("db", table, col.lower())
        prev = self.e.stored.get(key)
        site = (self.fi.rel, node.line, node.col)
        if prev is not None:
            sites = prev[4] if site in prev[4] or len(prev[4]) >= 8 else prev[4] + (site,)
            self.e.stored[key] = (prev[0], prev[1], prev[2] | kinds, prev[3] or raw, sites)
        else:
            self.e.stored[key] = (self.fi.rel, node.line, kinds, raw, (site,))

    def _db_write_sql(self, qexpr, env, tenv, node):
        if self.e.stored_sources is not None:
            return
        text, taints = self._sql_text(qexpr, env, tenv)
        if not text or not taints:
            return
        w = parse_write(text)
        if w is None:
            return
        table, cols = w
        for col, val in cols.items():
            t = EMPTY
            for m in _PH_RX.finditer(val):
                t = t_union(t, taints[int(m.group(1))])
            self._db_record(table, col, t, node)

    def _db_write_array(self, table, arr, env, tenv, node, sanitised_xss=False):
        if self.e.stored_sources is not None or not table or arr is None:
            return
        if arr.kind == "Var" and isinstance(arr.name, str):
            nm = arr.name
            for k in list(env):
                if k.startswith(nm + "[") and k.endswith("]"):
                    self._db_record(table, k[len(nm) + 1:-1].strip("'\""), env[k], node, sanitised_xss)
            lit = self._lit_array_nodes.get(nm)
            if lit is None:
                return
            arr = lit
        if arr.kind != "Array":
            return
        for it in arr.items or []:
            if it is None or it.key is None or it.key.kind != "String":
                continue
            self._db_record(table, it.key.value, self.expr_quiet(it.value, env, tenv), node, sanitised_xss)

    def _table_arg(self, e):
        if e is None:
            return None
        if e.kind == "String":
            return norm_table(e.value or "")
        if e.kind == "BinOp" and e.op == "." and e.right.kind == "String":
            if e.left.kind == "PropFetch" and e.left.name in ("prefix", "base_prefix"):
                return norm_table(e.right.value)
            return None
        if e.kind == "Interp":
            lits = [p for p in e.parts if p.kind == "String"]
            dyn = [p for p in e.parts if p.kind != "String"]
            if len(lits) == 1 and all(p.kind == "PropFetch" and p.name in ("prefix", "base_prefix") for p in dyn):
                return norm_table(lits[0].value)
        return None

    def _model_table(self, fq):
        """Table of an Eloquent model class (its $table, else the pluralised name)."""
        cs = self.p.get_class(fq) if fq else None
        if cs is None:
            return None
        seen, cur, is_model = 0, cs, False
        while cur is not None and seen < 8:
            par = (cur.parent or "").lower()
            if par.endswith(("eloquent\\model", "\\model", "authenticatable", "\\pivot")) or par in ("model", "eloquent"):
                is_model = True
                break
            cur = self.p.get_class(cur.parent) if cur.parent else None
            seen += 1
        if not is_model:
            return None
        ps = cs.props.get("table") if hasattr(cs, "props") else None
        dv = getattr(ps, "node", None)
        dv = dv.get("default") if dv is not None and hasattr(dv, "get") else None
        if dv is not None and getattr(dv, "kind", None) == "String":
            return norm_table(dv.value)
        return norm_table(plural(fq.rsplit("\\", 1)[-1]))

    def _is_entity(self, fq):
        cs = self.p.get_class(fq) if fq else None
        return cs is not None and fq.split("\\")[-2:-1] in (["Entity"], ["Entities"], ["Document"])

    # ------------------------------------------------------------ reads
    def _db_shape(self, e, tenv):
        """What a value read from the database looks like: ("rows"|"row", table, cols)."""
        k = e.kind
        if k == "Call" and e.func.kind == "Name":
            n = e.func.name.lower().lstrip("\\")
            if n in _QUERY_FNS and e.args:
                i = _QUERY_FNS[n]
                a = e.args[i].value if -len(e.args) <= i < len(e.args) else None
                return self._select_shape(a)
            if n in _FETCH_FNS and e.args:
                a = e.args[0].value
                src = self.dbvars.get(a.name) if a.kind == "Var" and isinstance(a.name, str) else self._db_shape(a, tenv)
                if src is not None:
                    return ("rows" if _FETCH_FNS[n] == "rows" else "row", src[1], src[2]) if _FETCH_FNS[n] != "cell" \
                        else ("cell", src[1], src[2])
            if n in _WP_GETTERS:
                return ("rows" if n.endswith("s") else "row", _WP_GETTERS[n], [("*", "*")])
            return None
        if k == "MethodCall" and isinstance(e.name, str):
            n = e.name.lower()
            obj = e.obj
            if n in _WP_ROW_METHODS and e.args:
                sh = self._select_shape(e.args[0].value)
                if sh is not None:
                    return (_WP_ROW_METHODS[n] if _WP_ROW_METHODS[n] != "name" else "row", sh[1], sh[2])
                return None
            if n in ("query", "prepare", "executequery", "select") and e.args:
                sh = self._select_shape(e.args[0].value)
                if sh is not None:
                    return sh
            if n in _FETCH_METHODS:
                src = None
                if obj.kind == "Var" and isinstance(obj.name, str):
                    src = self.dbvars.get(obj.name)
                elif obj.kind in ("MethodCall", "StaticCall", "Call"):
                    src = self._db_shape(obj, tenv)
                if src is not None:
                    mode = _FETCH_METHODS[n]
                    if mode == "same":
                        return src
                    if mode == "cell":
                        return ("cell", src[1], src[2])
                    return ("rows" if mode == "rows" else "row", src[1], src[2])
            # DB::table('t')->where()->first() chains
            if n in _ELOQ_READS:
                root = obj
                while root.kind == "MethodCall":
                    root = root.obj
                tb = self._chain_table(root)
                if tb is not None and n in _ELOQ_TERMINAL:
                    return ("rows" if n in ("get", "all", "paginate", "findmany", "simplepaginate", "cursor", "lazy")
                            else "row", tb, [("*", "*")])
                if tb is not None:
                    return ("query", tb, [("*", "*")])
            return None
        if k == "StaticCall" and isinstance(e.name, str) and e.cls.kind == "Name":
            n = e.name.lower()
            tb = self._chain_table(e)
            if tb is not None and n in _ELOQ_TERMINAL:
                return ("rows" if n in ("get", "all", "paginate", "findmany", "cursor", "lazy") else "row",
                        tb, [("*", "*")])
            if tb is not None and n in _ELOQ_READS:
                return ("query", tb, [("*", "*")])
        if k == "New" and getattr(e, "cls", None) is not None and e.cls.kind == "Name":
            return None
        return None

    def _chain_table(self, root):
        if root.kind != "StaticCall" or root.cls.kind != "Name" or not isinstance(root.name, str):
            return None
        short = root.cls.name.rsplit("\\", 1)[-1].lower()
        if short == "db" and root.name.lower() == "table" and root.args:
            return self._table_arg(root.args[0].value)
        if root.name.lower() not in _ELOQ_READS:
            return None
        fq = self.p.resolve_class(root.cls.name, self.ctx)
        return self._model_table(fq)

    def _select_shape(self, a):
        if a is None:
            return None
        text, _t = self._sql_text_plain(a)
        if not text:
            return None
        s = parse_select(text)
        if s is None:
            return None
        return ("rows", s[0], s[1])

    def _sql_text_plain(self, a):
        parts = self._sql_parts(a)
        if not parts:
            return None, []
        text = ""
        for i, p in enumerate(parts):
            if p.kind == "String" or isinstance(p, _Lit):
                text += p.value or ""
            elif p.kind == "PropFetch" and p.name in ("prefix", "base_prefix"):
                continue
            else:
                text += _PH % i
        return text, []

    def _db_read(self, shape, col, node):
        """Source for a read of table.col, if request data was stored there."""
        ss = self.e.stored_sources
        if not ss or shape is None or col is None:
            return None
        table, cols = shape[1], shape[2]
        if not isinstance(col, int) and isinstance(col, str) and col.isdigit():
            col = int(col)
        if isinstance(col, int):
            if col < 0 or col >= len(cols) or cols[col][0] in (None, "*"):
                return None
            col = cols[col][0]
        else:
            col = col.lower()
            names = {a: c for c, a in cols if c}
            if col in names and names[col] != "*":
                col = names[col]
            elif not any(c == "*" for c, _a in cols):
                return None
        where = ss.get(("db", table, col))
        if where is None or len(where) < 4:
            return None
        raw = " raw" if where[3] else ""
        return self.source("stored db %s.%s%s (written from request data at %s:%d)"
                           % (table, col, raw, where[0], where[1]), node, where[2])

    def _df_array_dim(self, e):
        b = e.var
        if b.kind == "Var" and isinstance(b.name, str) and b.name in self.dbvars and e.dim is not None \
                and e.dim.kind in ("String", "Int"):
            sh = self.dbvars[b.name]
            if sh[0] in ("row", "rows") or sh[0] == "query":
                return self._db_read(sh, e.dim.value, e)
        # $rows[0]['col'] / $rows[$i]['col']
        if b.kind == "ArrayDim" and b.var.kind == "Var" and isinstance(b.var.name, str) and \
                self.dbvars.get(b.var.name, ("",))[0] == "rows" and e.dim is not None and e.dim.kind in ("String", "Int"):
            return self._db_read(self.dbvars[b.var.name], e.dim.value, e)
        return None

    def _df_prop(self, e, tenv):
        o = e.obj
        if not isinstance(e.name, str) or self.e.stored_sources is None:
            return None
        if o.kind == "Var" and isinstance(o.name, str) and o.name in self.dbvars:
            return self._db_read(self.dbvars[o.name], e.name, e)
        if o.kind in ("MethodCall", "StaticCall", "Call"):
            sh = self._db_shape(o, tenv)
            if sh is not None and sh[0] == "row":
                return self._db_read(sh, e.name, e)
        if o.kind == "Var" and o.name != "this":
            for fq in self.types.infer(o, tenv):
                tb = self._model_table(fq)
                if tb:
                    r = self._db_read(("row", tb, [("*", "*")]), e.name, e)
                    if r is not None:
                        return r
        return None

    # ------------------------------------------------- write call sites
    def _df_call(self, name, c, env, tenv):
        if self.e.stored_sources is not None:
            return
        if name in _QUERY_FNS and c.args:
            i = _QUERY_FNS[name]
            if -len(c.args) <= i < len(c.args):
                self._db_write_sql(c.args[i].value, env, tenv, c)
        elif name in _WP_INSERTS and c.args:
            table, i = _WP_INSERTS[name]
            # core runs kses / wp_filter_kses on post and comment fields for users
            # without unfiltered_html: stored HTML is filtered on write
            self._db_write_array(table, c.args[i].value, env, tenv, c, sanitised_xss=True)

    def _df_method(self, lname, c, obj, env, tenv):
        if self.e.stored_sources is not None:
            return
        rn = obj.name if obj.kind == "Var" and isinstance(obj.name, str) else None
        if lname in ("insert", "update", "replace") and rn == "wpdb" and c.args:
            self._db_write_array(self._table_arg(c.args[0].value), c.args[1].value if len(c.args) > 1 else None,
                                 env, tenv, c)
            return
        if lname in _QUERY_METHODS and c.args and lname not in ("insert", "update"):
            self._db_write_sql(c.args[0].value, env, tenv, c)
        if lname in ("insert", "update", "updateorinsert", "insertgetid", "upsert") and c.args:
            root = obj
            while root.kind == "MethodCall":
                root = root.obj
            tb = self._chain_table(root) if root.kind == "StaticCall" and root.cls.kind == "Name" and \
                root.cls.name.rsplit("\\", 1)[-1].lower() == "db" else None
            if tb:
                self._db_write_array(tb, c.args[-1].value if lname == "updateorinsert" else c.args[0].value,
                                     env, tenv, c)
                return
            if lname in ("insert", "update") and len(c.args) >= 2:
                # Laravel DB::insert('INSERT ...', [...]) is handled as SQL text
                self._db_write_sql(c.args[0].value, env, tenv, c)
        if lname in _ELOQ_WRITES_INST and c.args and rn is not None and rn != "this":
            for fq in self.types.infer(obj, tenv):
                tb = self._model_table(fq)
                if tb:
                    self._db_write_array(tb, c.args[0].value, env, tenv, c)
        # Doctrine: $e->setTitle($x) ... $em->persist($e)
        if lname.startswith("set") and len(lname) > 3 and len(c.args) == 1 and rn is not None:
            self._setters.setdefault(rn, []).append((lname[3:], self.expr_quiet(c.args[0].value, env, tenv)))
        if lname == "persist" and c.args and c.args[0].value.kind == "Var":
            v = c.args[0].value
            ent = None
            for fq in self.types.infer(v, tenv):
                ent = fq.rsplit("\\", 1)[-1].lower()
            if ent:
                for prop, t in self._setters.get(v.name, []):
                    self._db_record("entity:" + ent, prop, t, c)

    def _df_static(self, short, lname, fq, c, env, tenv):
        if self.e.stored_sources is not None:
            return
        if short == "db" and lname in ("insert", "update", "statement", "unprepared") and c.args:
            self._db_write_sql(c.args[0].value, env, tenv, c)
            return
        if lname in _ELOQ_WRITES_STATIC and c.args:
            tb = self._model_table(fq)
            if tb:
                arr = c.args[1].value if lname == "updateorcreate" and len(c.args) > 1 else c.args[0].value
                self._db_write_array(tb, arr, env, tenv, c)

    def _df_prop_write(self, tgt, t, tenv, node):
        """$post->title = <request data> on an Eloquent model."""
        if self.e.stored_sources is not None or not t or not isinstance(tgt.name, str):
            return
        o = tgt.obj
        if o.kind != "Var" or o.name == "this":
            return
        for fq in self.types.infer(o, tenv):
            tb = self._model_table(fq)
            if tb:
                self._db_record(tb, tgt.name, t, node)

    def _df_getter(self, lname, obj, c, tenv):
        """Doctrine getter on an entity whose setter stored request data."""
        if self.e.stored_sources is None or not lname.startswith(("get", "is")) or c.args:
            return None
        prop = lname[3:] if lname.startswith("get") else lname[2:]
        if not prop:
            return None
        for fq in self.types.infer(obj, tenv):
            r = self._db_read(("row", "entity:" + fq.rsplit("\\", 1)[-1].lower(), [("*", "*")]), prop, c)
            if r is not None:
                return r
        return None

    def _df_value(self, lname, c, obj):
        """DB::table('t')->value('col') / ->pluck('col')."""
        if self.e.stored_sources is None or lname not in ("value", "pluck") or not c.args:
            return None
        a = c.args[0].value
        if a.kind != "String":
            return None
        sh = self._db_shape(obj, None) if obj.kind in ("MethodCall", "StaticCall") else None
        if sh is None:
            return None
        return self._db_read(sh, a.value, c)

    # -------------------------------------------------------- callbacks
    def _df_callback(self, name, c, ats, env, tenv):
        spec = _CALLBACKS.get(name)
        if spec is None:
            return None
        cbi, data, ret = spec
        if len(c.args) <= cbi or c.args[cbi] is None:
            return None
        keys = self._cb_keys(c.args[cbi].value, tenv)
        if not keys:
            return None
        if data == "rest":
            args = [t for i, t in enumerate(ats) if i != cbi]
        elif isinstance(data, str) and data.startswith("spread"):
            j = int(data[-1])
            args = [ats[j]] * 4 if len(ats) > j else []
        else:
            args = [ats[j] if j < len(ats) else EMPTY for j in data]
        if name in ("usort", "uasort", "uksort", "array_filter", "array_walk", "array_walk_recursive",
                    "preg_replace_callback"):
            args = [args[0] if args else EMPTY] + args[1:]
        out = EMPTY
        for k in keys:
            out = t_union(out, self.apply_summary(k, args, c, "callback", None))
        if ret == "cb":
            return out
        if ret == "data":
            return ats[data[0]] if len(ats) > data[0] else EMPTY
        if ret == "both":
            return t_union(out, ats[data[0]] if len(ats) > data[0] else EMPTY)
        return EMPTY

    def _cb_keys(self, e, tenv):
        if e.kind == "Var" and isinstance(e.name, str) and e.name in self.callables:
            e = self.callables[e.name]
        return self._callable_keys(e, tenv)

    def _df_hook_register(self, name, c, tenv):
        if name in ("add_filter", "add_action") and len(c.args) >= 2 and c.args[0].value.kind == "String":
            keys = self._cb_keys(c.args[1].value, tenv)
            if keys:
                self.e.hook_cbs.setdefault(c.args[0].value.value, set()).update(keys)

    def _df_hook_apply(self, name, c, ats):
        if name not in ("apply_filters", "do_action", "apply_filters_ref_array", "do_action_ref_array") \
                or not c.args or c.args[0].value.kind != "String":
            return None
        keys = self.e.hook_cbs.get(c.args[0].value.value)
        if not keys:
            return None
        args = ats[1:]
        if name.endswith("_ref_array"):
            args = [ats[1]] * 4 if len(ats) > 1 else []
        out = EMPTY
        for k in sorted(keys, key=str):
            out = t_union(out, self.apply_summary(k, args, c, "filter callback", None))
        if name.startswith("apply_filters"):
            return t_union(out, ats[1] if len(ats) > 1 else EMPTY)
        return EMPTY

    def _df_dynamic(self, fn, ats, c, tenv):
        if fn.name not in self.callables:
            return None
        keys = self._callable_keys(self.callables[fn.name], tenv)
        if not keys:
            return None
        out = EMPTY
        for k in keys:
            out = t_union(out, self.apply_summary(k, ats, c, "$%s()" % fn.name, None))
        return out


class _Lit:
    kind = "String"

    def __init__(self, v):
        self.value = v
