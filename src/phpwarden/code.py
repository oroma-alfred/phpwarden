"""phpwarden code: a small, high-signal first-party PHP code scanner.

Pure stdlib.  A regex-driven PHP tokenizer separates code from strings and
comments; a light, flow-insensitive, intra-function taint tracker follows
request data through simple assignments, concatenation and string
interpolation into dangerous sinks.  The bias is deliberately towards
precision: unknown functions and method calls *drop* taint, comparisons
yield booleans, and sanitizers clear the taint kinds they protect against.

Public API: scan_project, to_text, to_sarif, exit_code, list_rules.
"""
import bisect
import json
import os
import posixpath
import re

from phpwarden.code_rules import GADGET_PACKAGES, RULES, RULES_BY_ID, SEVERITIES, TAINT_SINKS

try:
    from phpwarden import __version__ as _VERSION
except Exception:  # pragma: no cover
    _VERSION = "0"

PHP_EXTS = (".php", ".phtml", ".inc")
SKIP_DIRS = {"vendor", "node_modules", ".git", ".svn", ".hg", ".idea", "bower_components"}
TEST_DIRS = {"test", "tests"}
MAX_FILES = 20000
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# ---------------------------------------------------------------------------
# Tokenizer
# Token = (type, value, pos); types: html str dstr bt cast var id num op
_OPEN_TAG = re.compile(r"<\?php\b|<\?=|<\?(?!xml)", re.I)
_TOKEN = re.compile(r"""
 (?P<ws>\s+)
|(?P<comment>//[^\n]*?(?=\?>|\n|$)|\#(?!\[)[^\n]*?(?=\?>|\n|$)|/\*.*?(?:\*/|\Z))
|(?P<close>\?>)
|(?P<heredoc><<<[ \t]*(?P<hq>["']?)(?P<hname>[A-Za-z_]\w*)(?P=hq)\r?\n)
|(?P<sq>'(?:[^'\\]|\\.)*'?)
|(?P<dq>"(?:[^"\\]|\\.)*"?)
|(?P<bt>`(?:[^`\\]|\\.)*`?)
|(?P<cast>\(\s*(?:int|integer|float|double|real|bool|boolean|string|array|object|unset|binary)\s*\))
|(?P<var>\$[A-Za-z_\x80-￿][\w\x80-￿]*)
|(?P<id>\\?[A-Za-z_\x80-￿][\w\x80-￿]*(?:\\[A-Za-z_\x80-￿][\w\x80-￿]*)*)
|(?P<num>0[xXbB][0-9a-fA-F_]+|\d[\d_]*(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+)
|(?P<op><=>|\*\*=|\.\.\.|<<=|>>=|===|!==|\?\?=|\?->|::|->|=>|==|!=|<>|<=|>=|&&|\|\||\+\+|--|\+=|-=|\*=|/=|\.=|%=|&=|\|=|\^=|<<|>>|\?\?|\#\[|[-+*/%=<>!.,;:?()\[\]{}&|^~@$])
""", re.X | re.S)
_CAST_NAME = re.compile(r"\w+")


def tokenize(src):
    toks = []
    pos, n = 0, len(src)
    append = toks.append
    while pos < n:
        m = _OPEN_TAG.search(src, pos)
        if not m:
            break
        pos = m.end()
        if m.group(0) == "<?=":
            append(("id", "echo", m.start()))
        while pos < n:
            mt = _TOKEN.match(src, pos)
            if not mt:
                pos += 1
                continue
            kind = mt.lastgroup
            if kind in ("hq", "hname"):
                kind = "heredoc"
            start = pos
            pos = mt.end()
            if kind == "ws" or kind == "comment":
                continue
            if kind == "close":
                append(("op", ";", start))
                break
            if kind == "heredoc":
                name = mt.group("hname")
                nowdoc = mt.group("hq") == "'"
                endm = re.compile(r"^[ \t]*" + re.escape(name) + r"\b", re.M).search(src, pos)
                body_end = endm.start() if endm else n
                body = src[pos:body_end]
                pos = endm.end() if endm else n
                append(("str" if nowdoc else "dstr", body, start))
            elif kind == "sq":
                append(("str", _unq(mt.group(0)[1:-1]), start))
            elif kind == "dq":
                append(("dstr", mt.group(0)[1:-1], start))
            elif kind == "bt":
                append(("bt", mt.group(0)[1:-1], start))
            elif kind == "cast":
                append(("cast", _CAST_NAME.search(mt.group(0)[1:]).group(0).lower(), start))
            elif kind == "id":
                append(("id", mt.group(0).lstrip("\\"), start))
            else:
                append((kind, mt.group(0), start))
    return toks


def _unq(s):
    return s.replace("\\'", "'").replace("\\\\", "\\")


# ---------------------------------------------------------------------------
# Taint vocabulary
ALL = frozenset({"sql", "xss", "cmd", "path", "incl", "code", "url", "redirect", "deser",
                 "ldap", "xpath", "session", "env"})
NONE = frozenset()
# Extra kinds that are not part of ALL (a plain request value does not carry them):
#   sqlq    a value that went through an SQL string escaper: safe inside quotes only
#   upname  derived from a client-supplied upload file name ($_FILES[..]['name'])
ALLX = ALL | {"sqlq", "upname"}
# Direct request input ($_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES, request objects,
# php://input) carries the extra marker "src". $_SERVER keys do not: a function that
# returns the current URI is not exported to other files as "returns request data".
STRONG = ALL | {"src"}
SQL_ESCAPERS = {"mysqli_real_escape_string", "mysql_real_escape_string", "mysql_escape_string",
                "pg_escape_string", "sqlite_escape_string", "addslashes", "esc_sql"}
SQL_ESCAPE_METHODS = {"escape_string", "real_escape_string", "escape"}
GUARD_FNS = {"is_numeric", "ctype_digit", "ctype_alnum", "ctype_alpha", "ctype_xdigit", "is_int",
             "is_integer", "is_float"}
EXIT_KW = {"die", "exit", "return", "throw", "continue", "break", "wp_die", "wp_send_json_error",
           "wp_send_json", "abort"}
# WordPress path validators: they return 0 (falsy) for a safe path and an error
# code or WP_Error (truthy) otherwise. validate_file_to_edit() dies on a bad file.
VALIDATORS = {"validate_file", "validate_plugin", "validate_theme_requirements"}
# Calls that end the request unless their check passes. The variables named in
# the checked value are trusted afterwards: a nonce bound to the exact value
# (check_admin_referer('activate-plugin_' . $plugin)) authenticates it, the
# same reasoning as hash_equals().
STATEMENT_GUARDS = {"validate_file_to_edit": 0, "check_admin_referer": 0, "check_ajax_referer": 0}
UPLOAD_CHECKS = {"getimagesize", "exif_imagetype", "finfo_file", "finfo_open", "finfo", "mime_content_type",
                 "wp_check_filetype", "wp_check_filetype_and_ext", "wp_handle_upload", "wp_handle_sideload",
                 "getimagesizefromstring"}
_TLS_COND = re.compile(r"(?i)verif|ssl|secure|debug")
_SAFE_CLASS = re.compile(r"(?:[A-Za-z0-9_\-]|\\d|\\w)+")


def _minus(taint, kinds):
    """taint without `kinds`; also drops the per-parameter markers ("sql@0") of those kinds."""
    return {x for x in taint if x.partition("@")[0] not in kinds}


def _real(taint):
    out = {x for x in taint if "@" not in x}
    return out if out - {"src"} else set()


def _pat_body(pat):
    if not pat or len(pat) < 3 or pat[0].isalnum() or pat[0] in "\\ ":
        return None, ""
    end = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(pat[0], pat[0])
    e = pat.rfind(end)
    if e <= 0:
        return None, ""
    return pat[1:e], pat[e + 1:]


def _whitelist_pattern(pat):
    """/^[a-z0-9_]+$/ style: anchored at both ends, one safe character class."""
    body, flags = _pat_body(pat)
    if body is None or "m" in flags:
        return False
    m = re.fullmatch(r"\^(?:\[([^\]\^][^\]]*)\]|\\d|\\w)(?:[+*]|\{\d+(?:,\d*)?\})?\$", body)
    return bool(m) and (m.group(1) is None or bool(_SAFE_CLASS.fullmatch(m.group(1))))


def _negclass_pattern(pat):
    """|[^a-z0-9_]| style: matches when the value has any character outside a safe class."""
    body, _flags = _pat_body(pat)
    if body is None:
        return False
    m = re.fullmatch(r"\[\^([^\]]+)\]\+?", body)
    return bool(m) and bool(_SAFE_CLASS.fullmatch(m.group(1)))
SUPERGLOBALS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES",
                "$HTTP_GET_VARS", "$HTTP_POST_VARS", "$HTTP_COOKIE_VARS"}
SERVER_KEYS = {"QUERY_STRING", "REQUEST_URI", "PHP_SELF", "PATH_INFO", "PATH_TRANSLATED", "ORIG_PATH_INFO"}
FILES_SAFE_KEYS = {"tmp_name", "size", "error"}
REQ_RECEIVERS = {"request", "req", "input"}
REQ_METHODS = {"input", "get", "query", "post", "all", "cookie", "header", "string", "str", "json",
               "only", "except", "getpost", "getget", "getvar", "getcookie", "getquery", "param",
               "getparam", "getqueryparams", "getparsedbody", "getcontent", "post_get", "get_post"}
BAG_NAMES = {"query", "request", "cookies", "headers", "attributes"}
STATIC_SOURCES = {("request", m) for m in REQ_METHODS} | {("input", m) for m in REQ_METHODS}

_X = {"xss"}
SANITIZERS = {
    # clear everything (numeric / strict tokens)
    **{f: ALLX for f in ("intval", "floatval", "doubleval", "boolval", "absint", "count", "sizeof",
                        "strlen", "mb_strlen", "is_numeric", "is_int", "is_string", "isset", "empty",
                        "in_array", "array_key_exists", "md5", "sha1", "hash", "hash_hmac", "crc32",
                        "password_hash", "password_verify", "sanitize_key", "sanitize_title",
                        "sanitize_user", "wp_create_nonce", "ctype_digit", "ctype_alnum",
                        "preg_match", "strpos", "stripos", "str_contains", "uniqid", "round",
                        "floor", "ceil", "abs", "max", "min", "number_format", "gettype",
                        "array_sum", "time", "strtotime", "date", "checkdate", "file_exists",
                        "is_file", "is_dir", "bin2hex", "base_convert", "spl_object_hash")},
    **{f: frozenset(_X) for f in ("htmlspecialchars", "htmlentities", "esc_html", "esc_attr", "esc_textarea",
                                  "esc_js", "wp_kses", "wp_kses_post", "wp_kses_data", "e", "strip_tags",
                                  "sanitize_text_field", "sanitize_textarea_field", "json_encode",
                                  "wp_json_encode", "esc_html__", "esc_attr__")},
    **{f: frozenset({"xss", "redirect", "url"}) for f in ("esc_url", "esc_url_raw", "sanitize_url")},
    **{f: frozenset({"xss", "redirect"}) for f in ("urlencode", "rawurlencode", "http_build_query")},
    "esc_sql": frozenset({"sql"}), "mysqli_real_escape_string": frozenset({"sql"}),
    "mysql_real_escape_string": frozenset({"sql"}), "mysql_escape_string": frozenset({"sql"}),
    "pg_escape_string": frozenset({"sql"}), "pg_escape_literal": frozenset({"sql"}),
    "sqlite_escape_string": frozenset({"sql"}), "addslashes": frozenset({"sql"}),
    "escapeshellarg": frozenset({"cmd"}), "escapeshellcmd": frozenset({"cmd"}),
    "basename": frozenset({"path", "incl"}), "sanitize_file_name": frozenset({"path", "incl", "xss"}),
    "realpath": frozenset({"incl"}),
    "ldap_escape": frozenset({"ldap"}),
    "wp_validate_redirect": frozenset({"redirect"}), "wp_sanitize_redirect": NONE,
}
SANITIZING_METHODS = {"prepare": frozenset({"sql"}), "quote": frozenset({"sql"}),
                      "escape_string": frozenset({"sql"}), "real_escape_string": frozenset({"sql"}),
                      "escape": frozenset({"sql"}), "esc_like": NONE}
PROPAGATORS = {"trim", "ltrim", "rtrim", "strtolower", "strtoupper", "ucfirst", "lcfirst", "ucwords",
               "sprintf", "vsprintf", "implode", "join", "str_replace", "str_ireplace", "substr",
               "mb_substr", "urldecode", "rawurldecode", "base64_decode", "stripslashes", "stripcslashes",
               "json_decode", "html_entity_decode", "htmlspecialchars_decode", "strrev", "str_pad",
               "nl2br", "wp_unslash", "stripslashes_deep", "array_values", "reset", "end", "current",
               "array_merge", "array_shift", "array_pop", "explode", "str_repeat", "preg_replace",
               "strval", "trim", "gzinflate", "gzuncompress", "str_rot13", "hex2bin", "convert_uuencode",
               "iconv", "mb_convert_encoding", "utf8_decode", "utf8_encode", "wp_specialchars_decode",
               "array_slice", "strstr", "substr_replace", "ltrim", "parse_url", "pathinfo", "dirname",
               "untrailingslashit", "trailingslashit", "rawurlencode_deep", "strtr", "vsprintf"}
FILTER_SAFE = re.compile(r"^FILTER_(VALIDATE_(INT|FLOAT|BOOL|BOOLEAN|EMAIL|IP|MAC|DOMAIN)|SANITIZE_NUMBER_(INT|FLOAT))$")
FILTER_XSS = re.compile(r"^FILTER_SANITIZE_(SPECIAL_CHARS|FULL_SPECIAL_CHARS|ENCODED)$")
CMP_OPS = {"==", "===", "!=", "!==", "<>", "<", ">", "<=", ">=", "<=>", "instanceof", "&&", "||", "and", "or", "xor"}
INT_CASTS = {"int", "integer", "float", "double", "real", "bool", "boolean", "unset"}
INCLUDES = {"include", "include_once", "require", "require_once"}

SECRET_NAME = re.compile(r"(?:^|_)(pass|passwd|password|pwd|secret|api_?key|apikey|access_?key|auth_?token|"
                         r"access_?token|secret_?key|private_?key|client_?secret|token|app_?secret|db_?pass(?:word)?)$", re.I)
SECRET_PLACEHOLDER = re.compile(r"change|your|example|xxx|placeholder|dummy|sample|test|secret|password|"
                                r"<|>|\{|\}|%|\$|env|null|todo|fixme|\*\*\*|\.\.\.|insert|replace|enter|"
                                r"default|redacted|here", re.I)
PASSWORD_VAR = re.compile(r"(?i)(pass(wd|word)?|pwd)")
SECRET_VAR = re.compile(r"(?i)(token|secret|nonce|password|passwd|salt|api_?key|otp|csrf|reset|activation|"
                        r"verification|verify_?code|session_?id|auth_?code)")
WEAK_RAND = {"rand", "mt_rand", "uniqid", "lcg_value", "str_shuffle", "microtime", "mt_srand"}
SESSIONISH = re.compile(r"(?i)(sess|auth|token|remember|login|jwt|sid)")
WP_WRITES = {"update_option", "add_option", "delete_option", "update_site_option", "wp_insert_user",
             "wp_update_user", "wp_delete_user", "wp_create_user", "wp_insert_post", "wp_update_post",
             "wp_delete_post", "wp_trash_post", "update_user_meta", "add_user_meta", "delete_user_meta",
             "update_post_meta", "add_post_meta", "delete_post_meta", "wp_set_password", "wp_set_current_user",
             "wp_set_auth_cookie", "move_uploaded_file", "file_put_contents", "unlink", "wp_handle_upload",
             "wp_insert_comment", "wp_delete_comment", "update_user_option", "set_role", "add_role",
             "wp_set_object_terms", "wp_insert_term", "wp_delete_term"}
WPDB_WRITES = {"query", "insert", "update", "delete", "replace"}
WP_GUARDS = {"check_ajax_referer", "wp_verify_nonce", "check_admin_referer", "current_user_can",
             "user_can", "current_user_can_for_blog", "is_super_admin"}
WP_NONCES = {"check_ajax_referer", "wp_verify_nonce", "check_admin_referer"}

_INTERP = re.compile(r"(?<!\\)\$\{?([A-Za-z_][\w]*)\}?(\[(?:'[^']*'|\"[^\"]*\"|[^\]]*)\])?")
_PEM = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_AWS = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")


def _is(t, typ, val=None):
    return t[0] == typ and (val is None or t[1] == val)


def _isop(t, val):
    return t[0] == "op" and t[1] == val


def _lname(name):
    return name.rsplit("\\", 1)[-1].lower()


def _match_close(toks, i):
    """toks[i] is an opening bracket; return index of matching close (or len)."""
    depth = 0
    n = len(toks)
    while i < n:
        t = toks[i]
        if t[0] == "op":
            v = t[1]
            if v in "([{" and len(v) == 1 or v == "#[":
                depth += 1
            elif v in ")]}" and len(v) == 1:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return n


def _split_args(toks, open_i):
    close = _match_close(toks, open_i)
    args, cur, depth = [], [], 0
    for t in toks[open_i + 1:close]:
        if t[0] == "op":
            if t[1] in ("(", "[", "{", "#["):
                depth += 1
            elif t[1] in (")", "]", "}"):
                depth -= 1
            elif t[1] == "," and depth == 0:
                args.append(cur)
                cur = []
                continue
        cur.append(t)
    if cur or args:
        args.append(cur)
    return args, close


def _strip_parens(toks):
    while len(toks) >= 2 and _isop(toks[0], "(") and _match_close(toks, 0) == len(toks) - 1:
        toks = toks[1:-1]
    return toks


def _literal_str(arg):
    arg = _strip_parens(arg)
    if len(arg) == 1 and arg[0][0] in ("str", "dstr") and (arg[0][0] == "str" or "$" not in arg[0][1]):
        return arg[0][1]
    return None


# sink index: fn name -> [spec], method name -> [spec], (cls, name) -> [spec]
_FN_SINKS, _METH_SINKS, _STATIC_SINKS = {}, {}, {}
for _s in TAINT_SINKS:
    if "fn" in _s:
        for _n in _s["fn"]:
            _FN_SINKS.setdefault(_n, []).append(_s)
    elif "method" in _s:
        for _n in _s["method"]:
            _METH_SINKS.setdefault(_n, []).append(_s)
    else:
        for _c in _s["static"]:
            for _n in _s["names"]:
                _STATIC_SINKS.setdefault((_c, _n), []).append(_s)
_RECV_RE = {}


def _arg_indices(spec, fname, nargs):
    a = spec.get("args")
    if isinstance(a, dict):
        a = a.get(fname, spec.get("default_args", [0]))
    if a == "*":
        return list(range(nargs))
    out = []
    for i in a:
        j = i if i >= 0 else nargs + i
        if 0 <= j < nargs:
            out.append(j)
    return out


# ---------------------------------------------------------------------------
_THIS_PROP = re.compile(r"\$this->(\w+)")
MAX_ROUNDS = 3             # project-wide summary rounds (wrappers of wrappers across files)
MAX_LOCAL_PASSES = 3       # summary passes inside one file


class FileScanner:
    def __init__(self, src, relpath, rules, ext=None, seed_env=None):
        self.src = src
        self.rel = relpath
        self.rules = rules
        # Project-wide summaries from the other files (see scan_project): None on
        # the first round. Keys: wrap, tret, retp, info, uniq, exports, resolve.
        self.ext = ext
        self.seed_env = dict(seed_env or {})
        self.lines = src.splitlines()
        self._nl = [m.start() for m in re.finditer("\n", src)]
        self.toks = tokenize(src)
        self.findings = {}
        self.funcs = {}      # name -> summary
        self.hooks = []      # (type, cbname, tok)
        self.rest = []       # (cbname or None, inline summary, tok)
        self.wrappers = {}   # fn name -> [(param index, taint kind, rule id, sink name)]
        self.tret = {}       # fn name -> taint kinds its return value carries
        self.gtaint = {}     # `global` variables given request data inside a function
        self.uploads = []    # (token, function-start index or None)
        self.pass_no = 1
        self.gstack = [set()]      # guarded variable expressions, per function scope
        self.glstack = [set()]     # names declared `global`, per function scope
        self.fn_stack = [None]     # current named function (None at file level / in closures)
        self.fstart = [None]       # token index of the innermost function body
        self.env0 = {}
        self.tls_opt = 0
        self.tls_tmp = False
        self.in_switch = 0         # inside switch { } / else { }: an assignment is one branch of several
        self._no_tret = False
        self.is_model = bool(re.search(r"extends\s+\\?(?:[\w\\]*\\)?(Model|Authenticatable|Pivot)\b", src))
        self.retp = {}       # fn name -> {param index: taint kinds its return value carries from that param}
        self.ret_seen = {}   # fn name -> positions of its `return <expr>` statements
        self.ret_hit = {}    # fn name -> positions of those that return request data
        self._no_props = False
        self.props = {}      # $this->prop -> real taint stored in it (class-local, within this file)
        self.setters = {}    # fn name -> [(param index, prop, kinds)]: method stores a parameter in a property
        self.cond_stack = [] # variables named by enclosing if/while conditions (None = not a condition block)
        self.incl_snap = {}  # included file -> real taint of the variables in scope at the include
        self.incl_targets = set()
        self.exports = {}    # file-level variables holding request data at the end of the file
        # names called in this file, and named functions defined here (with counts)
        toks = self.toks
        self.fwd_in_fn = set()   # local functions called from a function body before their definition
        self.fwd_any = set()     # ... called from anywhere before their definition
        self.fcalls = set()  # names called from inside function bodies
        self.calls, self.defcount = set(), {}
        src_ids = ("request", "get_query_var", "filter_input")
        has_source = bool(self.seed_env)
        n = len(toks)
        for k in range(n):
            t = toks[k]
            typ = t[0]
            if typ == "id":
                if k + 1 < n and toks[k + 1][0] == "op" and toks[k + 1][1] == "(":
                    self.calls.add(t[1].lower())
                low = t[1].lower()
                if low == "function" and k + 1 < n:
                    nxt = toks[k + 1] if not _isop(toks[k + 1], "&") else (toks[k + 2] if k + 2 < n else None)
                    if nxt is not None and nxt[0] == "id":
                        nm = nxt[1].lower()
                        self.defcount[nm] = self.defcount.get(nm, 0) + 1
                elif low in src_ids:
                    has_source = True
            elif typ == "var":
                if t[1] in SUPERGLOBALS or t[1] == "$_SERVER":
                    has_source = True
            elif typ in ("str", "dstr") and t[1] in ("php://input", "php://stdin"):
                has_source = True
        self.has_source = has_source

    # -- project-wide summaries --
    def _ext_has(self, table, name):
        """A summary from another file applies only to a name that is not defined
        here and that the project defines once (or identically everywhere)."""
        ext = self.ext
        return bool(ext) and name in ext[table] and name in ext["uniq"] and name not in self.defcount

    def _note_call(self, name):
        fwd = self.pass_no == 1 and name in self.defcount and name not in self.funcs
        if fwd:
            self.fwd_any.add(name)
        if self.fn_stack[-1]:
            self.fcalls.add(name)
            if fwd:
                self.fwd_in_fn.add(name)

    def _wraps(self, name, any_receiver=False):
        """(wrapper list, origin) for a call to `name`; origin is "file:line" for
        another file's function, None for a local one."""
        self._note_call(name)
        if name in self.wrappers and (not any_receiver or (self.ext and name in self.ext["uniq"])):
            return self.wrappers[name], None
        if self._ext_has("wrap", name):
            return self.ext["wrap"][name], self.ext["info"].get(name)
        return None, None

    def _ret_taint(self, name, args, env, local=True, any_receiver=False):
        """What a call returns: request data (tret) and/or taint passed through
        from its arguments (retp). Local summaries first, then other files."""
        res = set()
        self._note_call(name)
        loc_ok = local and (not any_receiver or (self.ext and name in self.ext["uniq"]))
        if loc_ok and name in self.tret and not self._no_tret:
            res |= self.tret[name]
        elif self._ext_has("tret", name):
            res |= self.ext["tret"][name]
        rp = self.retp.get(name) if loc_ok and name in self.retp else (
            self.ext["retp"][name] if self._ext_has("retp", name) else None)
        if rp:
            for pi, kinds in rp.items():
                if pi < len(args):
                    res |= {x for x in self._taint(args[pi], env) if x.partition("@")[0] in kinds}
        return res

    # -- location helpers --
    def _loc(self, pos):
        line = bisect.bisect_left(self._nl, pos) + 1
        col = pos - (self._nl[line - 2] + 1 if line > 1 else 0) + 1
        return line, col

    def _suppressed(self, rid, line):
        for ln in (line, line - 1):
            if 1 <= ln <= len(self.lines):
                text = self.lines[ln - 1]
                if "phpwarden-ignore" in text:
                    m = re.search(r"phpwarden-ignore(?::\s*([\w,\s-]+))?", text)
                    ids = (m.group(1) or "").replace(",", " ").split()
                    if not ids or rid in ids or "all" in ids:
                        return True
        return False

    def add(self, rid, tok, message=None):
        if rid not in self.rules:
            return
        line, col = self._loc(tok[2])
        key = (rid, line)
        if key in self.findings or self._suppressed(rid, line):
            return
        r = RULES_BY_ID[rid]
        snippet = self.lines[line - 1].strip()[:200] if line <= len(self.lines) else ""
        self.findings[key] = {"rule": rid, "title": r["title"], "severity": r["severity"], "cwe": r["cwe"],
                              "file": self.rel, "line": line, "column": col, "snippet": snippet,
                              "message": message or r["description"], "fix": r["fix"], "context": []}

    # -- taint evaluation --
    def _interp(self, raw, env):
        res = set()
        if "$" not in raw:
            return res
        if self.props and not self._no_props and "$this->" in raw:
            for m in _THIS_PROP.finditer(raw):
                res |= self.props.get(m.group(1).lower(), NONE)
        for m in _INTERP.finditer(raw):
            name = "$" + m.group(1)
            idx = (m.group(2) or "").strip("[]'\" ")
            if name in SUPERGLOBALS:
                if name == "$_FILES" and any(k in raw[m.end():m.end() + 20] or k == idx for k in FILES_SAFE_KEYS):
                    continue
                if (name + ("[" + idx + "]" if m.group(2) else "")) in self.gstack[-1]:
                    continue
                res |= STRONG
                if name == "$_FILES":
                    res.add("upname")
            elif name == "$_SERVER":
                if idx.startswith("HTTP_") or idx in SERVER_KEYS:
                    res |= ALL
            elif (name + ("[" + idx + "]" if m.group(2) else "")) not in self.gstack[-1]:
                res |= env.get(name, NONE)
        return res

    def _skip_var(self, toks, i):
        """Skip $var[..][..] and ->prop chains (not method calls); return end index."""
        n = len(toks)
        j = i + 1
        while j < n:
            if _isop(toks[j], "["):
                j = _match_close(toks, j) + 1
            elif toks[j][0] == "op" and toks[j][1] in ("->", "?->") and j + 1 < n and toks[j + 1][0] == "id" \
                    and not (j + 2 < n and _isop(toks[j + 2], "(")):
                j += 2
            else:
                break
        return j

    def _var_taint(self, toks, i, env):
        """Taint of variable expression starting at toks[i]; returns (taint, next_i)."""
        n = len(toks)
        name = toks[i][1]
        j = self._skip_var(toks, i)
        guards = self.gstack[-1]
        if guards and (name + "".join(t[1] for t in toks[i + 1:j])) in guards:
            return set(), j          # validated by an enclosing/earlier guard
        # method call directly on the chain?
        if j + 2 < n and toks[j][0] == "op" and toks[j][1] in ("->", "?->") and toks[j + 1][0] == "id" \
                and _isop(toks[j + 2], "("):
            meth = toks[j + 1][1].lower()
            recv = toks[j - 1][1].lstrip("$").lower() if j - 1 > i else name[1:].lower()
            args, close = _split_args(toks, j + 2)
            if (recv in REQ_RECEIVERS and meth in REQ_METHODS) or \
                    (recv in BAG_NAMES and j - 1 > i and meth in ("get", "all", "getint") and
                     name[1:].lower() in REQ_RECEIVERS and meth != "getint"):
                return set(STRONG), close + 1
            if meth in SANITIZING_METHODS:
                inner = [t for a in args for t in a]
                sub = self._taint(inner, env)
                out = _minus(sub, SANITIZING_METHODS[meth])
                if meth in SQL_ESCAPE_METHODS and "sql" in sub:
                    out.add("sqlq")
                return out, close + 1
            direct_this = name == "$this" and j - 1 == i
            return self._ret_taint(meth, args, env, local=True, any_receiver=not direct_this), close + 1
        if name in SUPERGLOBALS:
            idx = [t[1] for t in toks[i + 1:j] if t[0] in ("str", "dstr")]
            if name == "$_FILES" and any(k in FILES_SAFE_KEYS for k in idx):
                return set(), j
            return set(STRONG) | ({"upname"} if name == "$_FILES" else set()), j
        if name == "$_SERVER":
            idx = [t[1] for t in toks[i + 1:j] if t[0] in ("str", "dstr")]
            if idx and (idx[0].startswith("HTTP_") or idx[0] in SERVER_KEYS):
                return set(ALL), j
            return set(), j
        base = env.get(name, NONE)
        if "upname" in base and any(t[0] in ("str", "dstr") and t[1] in FILES_SAFE_KEYS for t in toks[i + 1:j]):
            return set(), j          # $upload['tmp_name'] / ['size'] / ['error']: set by PHP, not the client
        if name == "$this" and j > i + 2 and toks[i + 1][0] == "op" and toks[i + 1][1] in ("->", "?->") \
                and toks[i + 2][0] == "id" and not self._no_props:
            return set(self.props.get(toks[i + 2][1].lower(), NONE)), j
        return set(env.get(name, NONE)), j

    def _skip_operand(self, toks, i):
        n = len(toks)
        if i >= n:
            return i
        t = toks[i]
        if t[0] == "var":
            j = self._skip_var(toks, i)
            while j + 2 < n and toks[j][0] == "op" and toks[j][1] in ("->", "?->") and _isop(toks[j + 2], "("):
                j = _match_close(toks, j + 2) + 1
            return j
        if t[0] == "id" and i + 1 < n and _isop(toks[i + 1], "("):
            return _match_close(toks, i + 1) + 1
        if t[0] == "id" and i + 2 < n and _isop(toks[i + 1], "::"):
            j = i + 3
            if j < n and _isop(toks[j], "("):
                j = _match_close(toks, j) + 1
            return j
        if _isop(t, "("):
            return _match_close(toks, i) + 1
        if t[0] == "cast" or _isop(t, "-") or _isop(t, "+") or _isop(t, "@"):
            return self._skip_operand(toks, i + 1)
        return i + 1

    def _taint(self, toks, env):
        toks = _strip_parens(toks)          # ('DESC' === $order) is a comparison too
        n = len(toks)
        if not n:
            return set()
        # cond ? a : b  -> the condition only chooses; it is not part of the value
        depth, qi, ci, nest = 0, -1, -1, 0
        for k, t in enumerate(toks):
            if t[0] != "op":
                continue
            v = t[1]
            if v in ("(", "[", "{"):
                depth += 1
            elif v in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and v == "?":
                if qi < 0:
                    qi = k
                else:
                    nest += 1
            elif depth == 0 and v == ":" and qi >= 0:
                if nest:
                    nest -= 1
                else:
                    ci = k
                    break
        if qi >= 0 and ci > qi and not any(t[0] == "op" and t[1] in ("=", ".=", "??=", "=>", ",") for t in toks[:qi]):
            left = self._taint(toks[:qi], env) if ci == qi + 1 else self._taint(toks[qi + 1:ci], env)
            return left | self._taint(toks[ci + 1:], env)
        depth, has_q = 0, False
        for t in toks:
            if t[0] == "op":
                if t[1] in ("(", "[", "{"):
                    depth += 1
                elif t[1] in (")", "]", "}"):
                    depth -= 1
                elif depth == 0 and t[1] in ("?", "??"):
                    has_q = True
                elif depth == 0 and t[1] in CMP_OPS and not has_q:
                    return set()
                elif depth == 0 and t[1] == "!" and not has_q:
                    return set()
            elif t[0] == "id" and depth == 0 and t[1].lower() in CMP_OPS and not has_q:
                return set()
        res = set()
        i = 0
        while i < n:
            typ, val = toks[i][0], toks[i][1]
            if typ == "var":
                t, i = self._var_taint(toks, i, env)
                res |= t
                continue
            if typ in ("dstr", "bt"):
                res |= self._interp(val, env)
            elif typ == "cast":
                if val in INT_CASTS:
                    i = self._skip_operand(toks, i + 1)
                    continue
            elif typ == "id":
                low = _lname(val)
                if i + 1 < n and _isop(toks[i + 1], "("):
                    args, close = _split_args(toks, i + 1)
                    inner = [t for a in args for t in a]
                    after = close + 1
                    if low == "get_query_var" or low == "filter_input" and not self._filter_safe(inner):
                        res |= STRONG
                    elif low in ("file_get_contents", "fopen", "stream_get_contents") and args and \
                            _literal_str(args[0]) in ("php://input", "php://stdin"):
                        res |= STRONG
                    elif low == "request":
                        if args:
                            res |= STRONG
                        elif after + 2 < n and _isop(toks[after], "->") and toks[after + 1][0] == "id" \
                                and toks[after + 1][1].lower() in REQ_METHODS and _isop(toks[after + 2], "("):
                            res |= STRONG
                            after = _match_close(toks, after + 2) + 1
                        elif after + 1 < n and _isop(toks[after], "->"):
                            after = self._skip_chain(toks, after)
                    elif low in ("filter_var",):
                        if not self._filter_safe(inner):
                            sub = self._taint(args[0], env) if args else set()
                            if any(t[0] == "id" and FILTER_XSS.match(t[1]) for t in inner):
                                sub = _minus(sub, _X)
                            res |= sub
                    elif low == "preg_replace" and len(args) >= 3 and _negclass_pattern(_literal_str(args[0]) or "") \
                            and re.fullmatch(r"[A-Za-z0-9_\-]*", "!" if _literal_str(args[1]) is None else _literal_str(args[1])):
                        pass    # everything outside a safe character class was removed
                    elif self._ext_extract(low, args):
                        # the part after the last dot cannot contain ".." or lead a path
                        res |= _minus(self._taint(inner, env), {"path", "incl"})
                    elif low in SANITIZERS:
                        sub = self._taint(inner, env)
                        res |= _minus(sub, SANITIZERS[low])
                        if low in SQL_ESCAPERS and "sql" in sub:
                            res.add("sqlq")     # safe inside quotes only
                    elif low in PROPAGATORS:
                        res |= self._taint(inner, env)
                    else:
                        res |= self._ret_taint(low, args, env)
                    if after < n and toks[after][0] == "op" and toks[after][1] in ("->", "?->"):
                        after = self._skip_chain(toks, after)
                    i = after
                    continue
                if i + 2 < n and _isop(toks[i + 1], "::") and toks[i + 2][0] == "id":
                    cls, meth = low, toks[i + 2][1].lower()
                    j = i + 3
                    if j < n and _isop(toks[j], "("):
                        close = _match_close(toks, j)
                        if (cls, meth) in STATIC_SOURCES:
                            res |= STRONG
                        else:
                            sargs, _ = _split_args(toks, j)
                            res |= self._ret_taint(meth, sargs, env, local=cls in ("self", "static"),
                                                   any_receiver=cls not in ("self", "static"))
                        j = close + 1
                    i = j
                    continue
            elif typ == "op" and val in ("->", "?->"):
                i = self._skip_chain(toks, i)
                continue
            i += 1
        return res

    def _skip_chain(self, toks, i):
        n = len(toks)
        while i + 1 < n and toks[i][0] == "op" and toks[i][1] in ("->", "?->"):
            i += 2
            if i < n and _isop(toks[i], "("):
                i = _match_close(toks, i) + 1
        return i

    @staticmethod
    def _filter_safe(inner):
        return any(t[0] == "id" and FILTER_SAFE.match(t[1]) for t in inner)

    @staticmethod
    def _ext_extract(low, args):
        """Is this call taking a file extension (the text after the last dot)?"""
        if low == "pathinfo":
            return any(t[0] == "id" and t[1] == "PATHINFO_EXTENSION" for a in args[1:] for t in a)
        if low == "strrchr":
            return len(args) >= 2 and _literal_str(args[1]) == "."
        if low == "substr":
            return len(args) == 2 and any(t[0] == "id" and t[1].lower() == "strrpos" for t in args[1]) and \
                any(t[0] in ("str", "dstr") and t[1] == "." for t in args[1])
        if low == "end":
            return bool(args) and any(t[0] == "id" and t[1].lower() == "explode" for t in args[0]) and \
                any(t[0] in ("str", "dstr") and t[1] == "." for t in args[0])
        return False

    # -- SQL escaping only protects inside quotes --
    def _sqlq_unquoted(self, toks, env):
        """True when an SQL-escaped (not cast) value is placed OUTSIDE quotes in the
        string this expression builds, e.g. "WHERE id = $id". Only top-level
        concatenation and interpolation are looked at; a value with no literal
        text before it in this expression is not judged."""
        state = [None]
        seen = [False]

        def feed(text):
            q = state[0]
            for ch in text:
                if ch == "\\":
                    continue
                if q is None:
                    if ch in "'\"":
                        q = ch
                elif ch == q:
                    q = None
            state[0] = q
            if text:
                seen[0] = True

        def bad(tt):
            return "sqlq" in tt and "sql" not in tt and seen[0] and state[0] is None

        i, n = 0, len(toks)
        while i < n:
            t = toks[i]
            typ = t[0]
            if typ == "str":
                feed(t[1])
            elif typ == "dstr":
                last = 0
                for m in _INTERP.finditer(t[1]):
                    feed(t[1][last:m.start()])
                    name = "$" + m.group(1)
                    idx = (m.group(2) or "").strip("[]'\" ")
                    if name not in SUPERGLOBALS and name != "$_SERVER" and \
                            (name + ("[" + idx + "]" if m.group(2) else "")) not in self.gstack[-1] and \
                            bad(env.get(name, NONE)):
                        return True
                    last = m.end()
                feed(t[1][last:])
                seen[0] = True
            elif typ == "var":
                tt, j = self._var_taint(toks, i, env)
                if bad(tt):
                    return True
                i = j
                continue
            elif typ == "id" and i + 1 < n and _isop(toks[i + 1], "("):
                close = _match_close(toks, i + 1)
                if bad(self._taint(toks[i:close + 1], env)):
                    return True
                i = close + 1
                continue
            elif _isop(t, "("):
                close = _match_close(toks, i)
                if bad(self._taint(toks[i + 1:close], env)):
                    return True
                i = close + 1
                continue
            i += 1
        return False

    # -- validation guards --
    def _var_key(self, toks):
        toks = _strip_parens(toks)
        if not toks or toks[0][0] != "var" or self._skip_var(toks, 0) != len(toks):
            return None
        return toks[0][1] + "".join(t[1] for t in toks[1:])

    @staticmethod
    def _split_top(toks, ops):
        """Split at depth 0 on any of `ops`; also report whether a ternary is present."""
        parts, cur, depth = [], [], 0
        for t in toks:
            if t[0] == "op" and t[1] in ("(", "[", "{"):
                depth += 1
            elif t[0] == "op" and t[1] in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and (t[0] == "op" and t[1] in ops or t[0] == "id" and t[1].lower() in ops):
                parts.append(cur)
                cur = []
                continue
            cur.append(t)
        parts.append(cur)
        return parts

    @staticmethod
    def _has_top(toks, ops):
        depth = 0
        for t in toks:
            if t[0] == "op" and t[1] in ("(", "[", "{"):
                depth += 1
            elif t[0] == "op" and t[1] in (")", "]", "}"):
                depth -= 1
            elif depth == 0 and (t[0] == "op" and t[1] in ops or t[0] == "id" and t[1].lower() in ops):
                return True
        return False

    def _call_guard(self, a):
        """a is exactly `fn(args)`: (keys validated when it is TRUE, keys validated when it is FALSE)."""
        if len(a) < 3 or a[0][0] != "id" or not _isop(a[1], "(") or _match_close(a, 1) != len(a) - 1:
            return set(), set()
        low = _lname(a[0][1])
        args, _ = _split_args(a, 1)
        key = None
        if low in GUARD_FNS and args:
            key = self._var_key(args[0])
        elif low == "in_array" and len(args) >= 3:
            lst = _strip_parens(args[1])
            strict = _strip_parens(args[2])
            if lst and all(t[0] in ("str", "num") or t[0] == "dstr" and "$" not in t[1] or t[0] == "op" and t[1] in ("[", "]", ",", "(", ")") or
                           t[0] == "id" and t[1].lower() == "array" for t in lst) and \
                    len(strict) == 1 and strict[0][1].lower() == "true":
                key = self._var_key(args[0])
        elif low in VALIDATORS and args:
            k = self._var_key(args[0])
            return set(), ({k} if k else set())            # truthy = invalid
        elif low == "is_wp_error" and args:
            inner = _strip_parens(args[0])
            if len(inner) >= 3 and inner[0][0] == "id" and _lname(inner[0][1]) in VALIDATORS:
                return self._call_guard(inner)
        elif low == "wp_verify_nonce" and len(args) >= 2:
            return self._vars_in(args[1]), set()           # value bound to the nonce action
        elif low == "hash_equals" and len(args) == 2:
            # a value whose MAC/signature matched is authenticated, not attacker-chosen
            keys = set()
            for a_ in args:
                for k in range(len(a_)):
                    if a_[k][0] == "var" and not (k and a_[k - 1][0] == "op" and a_[k - 1][1] in ("->", "::", "$")):
                        keys.add(a_[k][1] + "".join(t[1] for t in a_[k + 1:self._skip_var(a_, k)]))
            return keys, set()
        elif low == "preg_match" and len(args) >= 2:
            pat = _literal_str(args[0])
            if pat and _whitelist_pattern(pat):
                key = self._var_key(args[1])
            elif pat and _negclass_pattern(pat):
                k = self._var_key(args[1])
                return set(), ({k} if k else set())
        return ({key} if key else set()), set()

    def _guards_pos(self, cond):
        """Variable expressions known to be validated when `cond` is true."""
        cond = _strip_parens(cond)
        if not cond or self._has_top(cond, ("||", "or", "xor", "?", "??")):
            return set()
        parts = self._split_top(cond, ("&&", "and"))
        if len(parts) > 1:
            out = set()
            for p in parts:
                out |= self._guards_pos(p)
            return out
        a = cond
        if _isop(a[0], "!"):
            return self._guards_neg(a[1:])
        cmp_ = self._zero_cmp(a)
        if cmp_:
            op, rest = cmp_
            return self._guards_neg(rest) if op in ("===", "==") else self._guards_pos(rest)
        return self._call_guard(a)[0]

    @staticmethod
    def _zero_cmp(a):
        """`X === 0`, `0 !== X`, `X == false`...: (operator, X) or None."""
        if len(a) >= 3 and a[-2][0] == "op" and a[-2][1] in ("===", "==", "!==", "!=") and a[-1][1].lower() in ("false", "0"):
            return a[-2][1], a[:-2]
        if len(a) >= 3 and a[1][0] == "op" and a[1][1] in ("===", "==", "!==", "!=") and a[0][1].lower() in ("false", "0"):
            return a[1][1], a[2:]
        return None

    def _vars_in(self, toks):
        keys = set()
        for k in range(len(toks)):
            if toks[k][0] == "var" and not (k and toks[k - 1][0] == "op" and toks[k - 1][1] in ("->", "::", "$")):
                keys.add(toks[k][1] + "".join(t[1] for t in toks[k + 1:self._skip_var(toks, k)]))
        return keys

    def _guards_neg(self, cond):
        """Variable expressions known to be validated when `cond` is false."""
        cond = _strip_parens(cond)
        if not cond or self._has_top(cond, ("&&", "and", "xor", "?", "??")):
            return set()
        parts = self._split_top(cond, ("||", "or"))
        if len(parts) > 1:
            out = set()
            for p in parts:
                out |= self._guards_neg(p)
            return out
        a = cond
        if _isop(a[0], "!"):
            return self._guards_pos(a[1:])
        cmp_ = self._zero_cmp(a)
        if cmp_:
            op, rest = cmp_
            return self._guards_pos(rest) if op in ("===", "==") else self._guards_neg(rest)
        return self._call_guard(a)[1]

    def _block_exits(self, idx):
        """toks[idx] is `{`: does the block's last top-level statement leave (die/return/...)?"""
        toks = self.toks
        close = _match_close(toks, idx)
        depth, start, last = 0, idx + 1, None
        k = idx + 1
        while k < close:
            t = toks[k]
            if k == start and not (t[0] == "op" and t[1] in (";", "}")):
                last = k
            if t[0] == "op":
                if t[1] in ("(", "[", "{"):
                    depth += 1
                elif t[1] in (")", "]", "}"):
                    depth -= 1
                    if depth == 0 and t[1] == "}":
                        start = k + 1
                elif t[1] == ";" and depth == 0:
                    start = k + 1
            k += 1
        return last is not None and toks[last][0] == "id" and _lname(toks[last][1]) in EXIT_KW

    @staticmethod
    def _cond_of(part):
        """(keyword, condition tokens) when `part` is exactly an if/elseif/while header."""
        if len(part) >= 3 and part[0][0] == "id" and part[0][1].lower() in ("if", "elseif", "while") \
                and _isop(part[1], "(") and _match_close(part, 1) == len(part) - 1:
            return part[0][1].lower(), part[2:-1]
        return None, None

    @staticmethod
    def _tls_cond(cond):
        return any(t[0] in ("var", "str", "dstr", "id") and _TLS_COND.search(t[1]) for t in cond)

    def _parts(self, stmt):
        """Split one statement into control headers and the statement they prefix:
        `case 1: $x = ..`, `if (..): echo ..`, `else echo ..`, `if (..) die();`."""
        out = []
        while stmt:
            t0 = stmt[0]
            kw = t0[1].lower() if t0[0] == "id" else None
            n = len(stmt)
            if kw == "case":
                depth = q = 0
                cut = None
                for k in range(1, n):
                    t = stmt[k]
                    if t[0] != "op":
                        continue
                    if t[1] in ("(", "[", "{"):
                        depth += 1
                    elif t[1] in (")", "]", "}"):
                        depth -= 1
                    elif depth == 0 and t[1] == "?":
                        q += 1
                    elif depth == 0 and t[1] == ":":
                        if q:
                            q -= 1
                        else:
                            cut = k
                            break
                if cut is None:
                    break
                stmt = stmt[cut + 1:]
                continue
            if kw == "default" and n > 1 and _isop(stmt[1], ":"):
                stmt = stmt[2:]
                continue
            if kw == "else":
                stmt = stmt[2:] if n > 1 and _isop(stmt[1], ":") else stmt[1:]
                continue
            if kw == "do":
                stmt = stmt[1:]
                continue
            if kw in ("if", "elseif", "while", "for", "foreach", "switch") and n > 1 and _isop(stmt[1], "("):
                close = _match_close(stmt, 1)
                out.append(stmt[:close + 1])
                stmt = stmt[close + 1:]
                if stmt and _isop(stmt[0], ":"):
                    stmt = stmt[1:]
                continue
            break
        if stmt:
            out.append(stmt)
        return out

    # -- main walk --
    def _summary_key(self):
        return (repr(sorted((k, sorted(v)) for k, v in self.wrappers.items())),
                repr(sorted((k, sorted(v)) for k, v in self.tret.items())),
                repr(sorted((k, sorted((p, sorted(kk)) for p, kk in v.items())) for k, v in self.retp.items())),
                repr(sorted((k, sorted(v)) for k, v in self.setters.items())))

    def run(self):
        self._pass(dict(self.seed_env))
        # Summary passes: a function can call a wrapper defined further down, so
        # repeat while a summarised function is called here and summaries grow.
        for _ in range(MAX_LOCAL_PASSES - 1):
            # only a forward call to a function that turned out to have a summary
            # can change another function's summary
            # (pass-through summaries alone do not justify another pass: they are
            # common and rarely decide a finding)
            names = set(self.wrappers) | set(self.tret)
            if not (names & self.fwd_in_fn):
                break
            before = self._summary_key()
            self.fwd_in_fn = set()
            self._pass(dict(self.seed_env))
            if self._summary_key() == before:
                break
        # (other files' summaries and include seeds are known before the first pass,
        # so they need no second one)
        fwd_hit = (set(self.wrappers) | set(self.tret) | set(self.setters)) & self.fwd_any
        if fwd_hit or self.gtaint or self.props:
            # Functions are often defined after they are called (class methods,
            # helpers at the bottom of a file): go over the file once more with
            # the summaries from the first pass.
            self.pass_no = 2
            seed = dict(self.seed_env)
            for k, v in self.gtaint.items():
                seed[k] = seed.get(k, NONE) | v
            self._pass(seed)
        # file-level variables other files see through an include: only those that
        # hold direct request input (not the current URL, not derived leftovers)
        self.exports = {k: frozenset(_real(v)) for k, v in self.env0.items()
                        if "src" in v and _real(v) and k not in SUPERGLOBALS}
        for tok, start in self.uploads:
            rng = self.toks if start is None else self.toks[start:_match_close(self.toks, start) + 1]
            line = self._loc(tok[2])[0]
            if ("path-move-upload", line) not in self.findings and not self._has_upload_check(rng):
                self.add("upload-unrestricted", tok)
        return self

    @staticmethod
    def _has_upload_check(rng):
        ids = {t[1].lower() for t in rng if t[0] == "id"}
        if ids & UPLOAD_CHECKS:
            return True
        ext = "pathinfo_extension" in ids or "strrchr" in ids or "strrpos" in ids or \
            ("explode" in ids and "end" in ids) or any(t[0] in ("str", "dstr") and t[1] == "type" for t in rng)
        cmp_ = "in_array" in ids or "preg_match" in ids or "switch" in ids or "match" in ids or \
            any(t[0] == "op" and t[1] in ("==", "===", "!=", "!==") for t in rng)
        return ext and cmp_

    def _params(self, idx):
        """Parameter names of the function whose `function` keyword is toks[idx]."""
        toks = self.toks
        k = idx + 1
        while k < len(toks) and k < idx + 4 and not _isop(toks[k], "("):
            k += 1
        if k >= len(toks) or not _isop(toks[k], "("):
            return []
        args, _ = _split_args(toks, k)
        out = []
        for a in args:
            name = next((t[1] for t in a if t[0] == "var"), None)
            typed = any(t[0] == "id" and t[1].lower() in ("int", "float", "bool") for t in a)
            out.append(None if typed else name)
        return out

    @staticmethod
    def _is_match_head(stmt):
        if len(stmt) < 3 or not _isop(stmt[-1], ")"):
            return False
        for k in range(len(stmt) - 2, -1, -1):
            if stmt[k][0] == "id" and stmt[k][1].lower() == "match" and _isop(stmt[k + 1], "("):
                return _match_close(stmt, k + 1) == len(stmt) - 1
        return False

    def _open_block(self, header, idx):
        """An ordinary `{`: note what its condition proves about variables."""
        parts = self._parts(header)
        if parts and parts[-1][0][0] == "id" and parts[-1][0][1].lower() == "switch":
            self.in_switch += 1
            return {"switch": True}
        m = {}
        if header and header[0][0] == "id" and header[0][1].lower() in ("else", "elseif"):
            # an else/elseif branch does not undo what a sibling branch assigned
            self.in_switch += 1
            m["switch"] = True
        kw, cond = self._cond_of(parts[-1]) if parts else (None, None)
        if kw is None:
            return m or None
        if kw in ("if", "elseif"):
            self.cond_stack.append({"vars": {t[1] for t in cond if t[0] == "var"}, "saved": {}})
            m["cond"] = True
        pos = self._guards_pos(cond) - self.gstack[-1]
        if pos:
            self.gstack[-1] |= pos
            m["pos"] = pos
        if kw != "while":
            neg = self._guards_neg(cond)
            if neg and self._block_exits(idx):
                m["neg"] = neg
        if self._tls_cond(cond):
            self.tls_opt += 1
            m["tls"] = True
        return m or None

    def _pass(self, seed=None):
        toks = self.toks
        env_stack = [dict(seed or {})]
        self.env0 = env_stack[0]
        self.gstack = [set()]
        self.glstack = [set()]
        self.fn_stack = [None]
        self.fstart = [None]
        self.tls_opt = 0
        self.in_switch = 0
        self.cond_stack = []
        brace = []           # entries: None, "expr", (fname, start_idx) or a guard dict
        stmt = []
        pending = None       # ('named', name, params) | ('closure',) when 'function' seen
        pdepth = 0
        for idx, t in enumerate(toks):
            typ, val = t[0], t[1]
            if typ == "op":
                if val in ("(", "["):
                    pdepth += 1
                elif val in (")", "]"):
                    pdepth = max(0, pdepth - 1)
                if val == "{":
                    if stmt and (stmt[-1][0] == "op" and stmt[-1][1] in ("$", "->") or
                                 not pending and self._is_match_head(stmt)):
                        brace.append("expr")
                        stmt.append(t)
                        continue
                    header = stmt
                    self._process(stmt, env_stack[-1])
                    stmt = []
                    pdepth = 0
                    if pending:
                        if pending[0] == "named":
                            env = {}
                            if self.pass_no == 1:      # parameter markers: "sql@0" = "argument 0, as SQL"
                                for pi, pn in enumerate(pending[2]):
                                    if pn:
                                        env[pn] = frozenset("%s@%d" % (k, pi) for k in ALL)
                            env_stack.append(env)
                            self.gstack.append(set())
                            self.glstack.append(set())
                            self.fn_stack.append(pending[1])
                        else:
                            env_stack.append(dict(env_stack[-1]))
                            self.gstack.append(set(self.gstack[-1]))
                            self.glstack.append(set(self.glstack[-1]))
                            self.fn_stack.append(None)
                        self.fstart.append(idx)
                        brace.append((pending[1] if pending[0] == "named" else None, idx))
                        pending = None
                    else:
                        brace.append(self._open_block(header, idx))
                    continue
                if val == "}":
                    m = brace.pop() if brace else None
                    if m == "expr":
                        stmt.append(t)
                        continue
                    self._process(stmt, env_stack[-1])
                    stmt = []
                    pdepth = 0
                    if isinstance(m, tuple):
                        if len(env_stack) > 1:
                            env_stack.pop()
                            self.gstack.pop()
                            self.glstack.pop()
                            self.fn_stack.pop()
                            self.fstart.pop()
                        if m[0]:
                            self._summarize_func(m[0], m[1], idx)
                    elif isinstance(m, dict):
                        if "pos" in m:
                            self.gstack[-1] -= m["pos"]
                        if "neg" in m:
                            self.gstack[-1] |= m["neg"]
                        if "tls" in m:
                            self.tls_opt = max(0, self.tls_opt - 1)
                        if "switch" in m:
                            self.in_switch = max(0, self.in_switch - 1)
                        if "cond" in m and self.cond_stack:
                            fr = self.cond_stack.pop()
                            env = env_stack[-1]
                            for k, old in fr["saved"].items():
                                env[k] = env.get(k, NONE) | old
                    continue
                if val == ";" and pdepth == 0:
                    self._process(stmt, env_stack[-1])
                    stmt = []
                    pending = None
                    continue
            elif typ == "id" and val.lower() in ("function", "fn") and val.lower() == "function":
                nxt = toks[idx + 1] if idx + 1 < len(toks) else None
                if nxt is not None and _isop(nxt, "&"):
                    nxt = toks[idx + 2] if idx + 2 < len(toks) else None
                if nxt is not None and nxt[0] == "id":
                    pending = ("named", nxt[1].lower(), self._params(idx))
                else:
                    pending = ("closure",)
            stmt.append(t)
        self._process(stmt, env_stack[-1])
        return self

    def _summarize_func(self, name, start, end):
        body = self.toks[start:end]
        writes = guards = nonce = False
        for k, t in enumerate(body):
            if t[0] != "id":
                continue
            low = _lname(t[1])
            nxt = body[k + 1] if k + 1 < len(body) else None
            if nxt is None or not _isop(nxt, "("):
                continue
            prev = body[k - 1] if k else None
            if prev is not None and prev[0] == "op" and prev[1] in ("->", "::"):
                recv = body[k - 2][1].lstrip("$").lower() if k >= 2 else ""
                if recv == "wpdb" and low in WPDB_WRITES:
                    if low != "query":
                        writes = True
                    else:  # only data-changing SQL counts as a write
                        q = body[k + 2] if k + 2 < len(body) else None
                        if q is not None and q[0] in ("str", "dstr") and re.match(
                                r"\s*(insert|update|delete|replace|drop|alter|truncate|create)\b", q[1], re.I):
                            writes = True
                continue
            if low in WP_WRITES:
                writes = True
            if low in WP_GUARDS:
                guards = True
            if low in WP_NONCES:
                nonce = True
        line, _ = self._loc(self.toks[start][2])
        self.funcs[name] = {"writes": writes, "guards": guards, "nonce": nonce, "file": self.rel, "line": line}

    def _process(self, stmt, env):
        if not stmt:
            return
        parts = self._parts(stmt)
        tmp = set()
        guards = self.gstack[-1]
        for k, p in enumerate(parts):
            self._scan_sinks(p, env)
            self._patterns(p, env)
            self._assign(p, env)
            head = p[0][1].lower() if p[0][0] == "id" else ""
            if head in STATEMENT_GUARDS and len(p) > 2 and _isop(p[1], "(") and _match_close(p, 1) == len(p) - 1:
                gargs, _ = _split_args(p, 1)
                gi = STATEMENT_GUARDS[head]
                if gi < len(gargs):
                    self.gstack[-1] |= self._vars_in(gargs[gi])
            if head == "global":
                for t in p[1:]:
                    if t[0] == "var":
                        self.glstack[-1].add(t[1])
                        if env is not self.env0 and self.env0.get(t[1]):
                            env[t[1]] = env.get(t[1], NONE) | self.env0[t[1]]
            elif head == "return" and self.pass_no == 1 and self.fn_stack[-1] and len(p) > 1:
                fn = self.fn_stack[-1]
                # a property's taint belongs to whatever request set it; it is not
                # something the method returns on every call
                self._no_props = True
                tt = self._taint(p[1:], env)
                self._no_props = False
                real = _real(tt)
                self.ret_seen.setdefault(fn, set()).add(p[0][2])
                if real:
                    self.ret_hit.setdefault(fn, set()).add(p[0][2])
                if real:
                    self.tret[fn] = self.tret.get(fn, frozenset()) | real
                for x in tt:
                    if "@" in x:
                        kind, _, pi = x.partition("@")
                        d = self.retp.setdefault(fn, {})
                        d[int(pi)] = d.get(int(pi), frozenset()) | {kind}
            if k + 1 < len(parts):             # brace-less body in the same statement
                kw, cond = self._cond_of(p)
                if kw in ("if", "elseif"):
                    body = parts[k + 1]
                    if body[0][0] == "id" and _lname(body[0][1]) in EXIT_KW:
                        guards |= self._guards_neg(cond)
                    else:
                        new = self._guards_pos(cond) - guards
                        guards |= new
                        tmp |= new
                    if self._tls_cond(cond):
                        self.tls_tmp = True
        if tmp:
            guards -= tmp
        self.tls_tmp = False

    def _assign(self, stmt, env):
        n = len(stmt)
        t0 = stmt[0]
        if t0[0] == "id" and t0[1].lower() == "for" and n > 3 and _isop(stmt[1], "("):
            # for ($i = 0, $j = 1; ...; ...): the init expressions are assignments
            close = _match_close(stmt, 1)
            inner = stmt[2:close]
            depth, cut = 0, len(inner)
            for k, t in enumerate(inner):
                if t[0] == "op" and t[1] in ("(", "[", "{"):
                    depth += 1
                elif t[0] == "op" and t[1] in (")", "]", "}"):
                    depth -= 1
                elif depth == 0 and _isop(t, ";"):
                    cut = k
                    break
            for seg in self._split_top(inner[:cut], (",",)):
                if seg and seg[0][0] == "var":
                    self._assign(seg, env)
            return
        if t0[0] == "id" and t0[1].lower() == "foreach" and n > 3:
            as_i = next((k for k, t in enumerate(stmt) if t[0] == "id" and t[1].lower() == "as"), None)
            if as_i:
                src = self._taint(stmt[2:as_i], env)
                for t in stmt[as_i + 1:]:
                    if t[0] == "var":
                        env[t[1]] = frozenset(src)
            return
        self._embedded_assigns(stmt, env)
        if t0[0] != "var":
            return
        j = self._skip_var(stmt, 0)
        if j >= n or stmt[j][0] != "op" or stmt[j][1] not in ("=", ".=", "??=", "+="):
            return
        rhs = stmt[j + 1:]
        if rhs and _isop(rhs[0], "&"):
            rhs = rhs[1:]
        taint = set(self._taint(rhs, env))
        if "sqlq" in taint and "sql" not in taint and stmt[j][1] in ("=", ".=") and self._sqlq_unquoted(rhs, env):
            taint.add("sql")      # escaped but placed outside quotes: still injectable
        taint = frozenset(taint)
        name = t0[1]
        if j > 1 and _isop(stmt[1], "->"):
            # $this->prop = ...: class-local property tracking (within this file)
            if name == "$this" and j == 3 and stmt[2][0] == "id":
                prop = stmt[2][1].lower()
                self._no_props = True            # no property-to-property chains: too coarse across methods
                taint = frozenset(self._taint(rhs, env))
                self._no_props = False
                real = _real(taint)
                if real:
                    self.props[prop] = self.props.get(prop, frozenset()) | real
                fn = self.fn_stack[-1]
                if fn and self.pass_no == 1:
                    for x in taint:
                        if "@" in x:
                            kind, _, pi = x.partition("@")
                            ent = (int(pi), prop, kind)
                            lst = self.setters.setdefault(fn, [])
                            if ent not in lst:
                                lst.append(ent)
            return
        if name in SUPERGLOBALS:
            return
        # inside `if (<something else>) { ... }` the assignment may not happen: it
        # holds inside the block, and after the block the variable may still have
        # its old value (a sanitiser behind an unrelated flag). Remember the old
        # value so the block's end can merge it back.
        if self.cond_stack:
            fr = self.cond_stack[-1]
            if name not in fr["vars"] and name not in fr["saved"]:
                fr["saved"][name] = env.get(name, NONE)
        if j > 1 or stmt[j][1] in (".=", "??=", "+=") or self.in_switch:
            env[name] = env.get(name, NONE) | taint
        else:
            env[name] = taint
        self._after_assign(name, env)

    def _after_assign(self, name, env):
        guards = self.gstack[-1]
        if guards:                 # a new value is not covered by an earlier check
            stale = {g for g in guards if g == name or g.startswith(name + "[")}
            if stale:
                guards -= stale
        if name in self.glstack[-1] and env is not self.env0:
            real = _real(env.get(name, NONE))
            if real:
                self.env0[name] = self.env0.get(name, NONE) | real
                self.gtaint[name] = self.gtaint.get(name, frozenset()) | real

    def _embedded_assigns(self, stmt, env):
        """Assignments that are not the statement itself: `if (($x = $_GET['a']))`,
        `$p ? $h = $_POST['h'] : $h = $_REQUEST['h']`, `$a = $b = $_GET['x']`."""
        n = len(stmt)
        found = []
        for k in range(1, n):
            if stmt[k][0] != "var":
                continue
            prev = stmt[k - 1]
            if prev[0] == "op" and prev[1] in ("->", "?->", "::", "$"):
                continue
            j = self._skip_var(stmt, k)
            if j < n and stmt[j][0] == "op" and stmt[j][1] in ("=", ".=", "??=") and not _isop(stmt[k + 1], "->"):
                found.append((k, j))
        if not found or any(t[0] == "id" and t[1].lower() in ("function", "fn") for t in stmt):
            return
        for k, j in reversed(found):
            depth = q = 0
            e = j + 1
            while e < n:
                t = stmt[e]
                if t[0] == "op":
                    v = t[1]
                    if v in ("(", "[", "{"):
                        depth += 1
                    elif v in (")", "]", "}"):
                        if depth == 0:
                            break
                        depth -= 1
                    elif depth == 0:
                        if v in (",", ";"):
                            break
                        if v == "?":
                            q += 1
                        elif v == ":":
                            if q == 0:
                                break
                            q -= 1
                e += 1
            name = stmt[k][1]
            if name in SUPERGLOBALS or name == "$this":
                continue
            taint = frozenset(self._taint(stmt[j + 1:e], env))
            env[name] = env.get(name, NONE) | taint     # weak update: it may be one branch of several
            self._after_assign(name, env)

    # -- sinks --
    def _fire(self, spec, fname, args, env, tok):
        for k in _arg_indices(spec, fname, len(args)):
            a = args[k]
            if a and a[0][0] == "id" and a[0][1].lower() in ("function", "fn", "static"):
                continue  # closure literal: its body is analysed separately
            t = self._taint(a, env)
            kind = spec["taint"]
            if kind not in t and kind == "sql" and "sqlq" in t and self._sqlq_unquoted(a, env):
                t = t | {"sql"}
            if kind not in t and self.pass_no == 1 and self.fn_stack[-1]:
                # a parameter of this function reaches the sink: remember it as a wrapper
                for x in t:
                    if x.startswith(kind + "@"):
                        w = (int(x.rsplit("@", 1)[1]), kind, spec["rule"], fname)
                        lst = self.wrappers.setdefault(self.fn_stack[-1], [])
                        if w not in lst:
                            lst.append(w)
            if kind in t:
                rid = spec["rule"]
                if spec.get("ssrf_rule"):
                    first = _strip_parens(a)[:1]
                    if first and first[0][0] in ("str", "dstr") and first[0][1].lower().startswith(("http:", "https:", "ftp:", "//")):
                        rid = spec["ssrf_rule"]
                self.add(rid, tok, "%s: request data reaches %s() (argument %d)." % (RULES_BY_ID[rid]["title"], fname, k + 1))
                return True
        return False

    def _scan_sinks(self, stmt, env):
        n = len(stmt)
        first = stmt[0]
        if first[0] == "id":
            kw = first[1].lower()
            if kw in ("echo", "print"):
                args, cur, depth = [], [], 0
                for t in stmt[1:]:
                    if t[0] == "op" and t[1] in "([{":
                        depth += 1
                    elif t[0] == "op" and t[1] in ")]}":
                        depth -= 1
                    elif _isop(t, ",") and depth == 0:
                        args.append(cur)
                        cur = []
                        continue
                    cur.append(t)
                args.append(cur)
                for a in args:
                    if "xss" in self._taint(a, env):
                        self.add("xss-echo", first)
                        break
        for i in range(n):
            t = stmt[i]
            typ = t[0]
            if typ == "bt":
                if "cmd" in self._interp(t[1], env):
                    self.add("cmd-backtick", t)
                continue
            if typ == "id":
                low = t[1].lower()
                if low in INCLUDES:
                    rest = stmt[i + 1:]
                    if "incl" in self._taint(rest, env):
                        self.add("include-tainted", t)
                    target = self.ext["resolve"](self.rel, rest) if self.ext and self.ext.get("resolve") else None
                    if target and target != self.rel:
                        self.incl_targets.add(target)
                        snap = {k: _real(v) for k, v in env.items() if "src" in v and _real(v)}
                        if snap:
                            cur = self.incl_snap.setdefault(target, {})
                            for k, v in snap.items():
                                cur[k] = cur.get(k, frozenset()) | v
                        # the included file's file-level variables now exist here
                        for k, v in self.ext["exports"].get(target, {}).items():
                            env[k] = env.get(k, NONE) | v
                    continue
                if i + 1 >= n or not _isop(stmt[i + 1], "("):
                    if i + 3 < n and _isop(stmt[i + 1], "::") and stmt[i + 2][0] == "id" and _isop(stmt[i + 3], "("):
                        key = (_lname(t[1]), stmt[i + 2][1].lower())
                        specs = _STATIC_SINKS.get(key)
                        if specs:
                            args, _ = _split_args(stmt, i + 3)
                            for s in specs:
                                if self._fire(s, key[1], args, env, t):
                                    break
                        else:
                            lst, origin = self._wraps(key[1], any_receiver=key[0] not in ("self", "static"))
                            if lst:
                                self._via_wrapper(key[1], _split_args(stmt, i + 3)[0], env, t, lst, origin)
                    continue
                prev = stmt[i - 1] if i else None
                if prev is not None and (prev[0] == "op" and prev[1] in ("->", "?->", "::") or
                                         prev[0] == "id" and prev[1].lower() in ("function", "new", "fn")):
                    if prev[0] == "op" and prev[1] in ("->", "?->"):
                        self._method_sink(stmt, i, env)
                        direct_this = i >= 2 and stmt[i - 2][0] == "var" and stmt[i - 2][1] == "$this"
                        lst, origin = self._wraps(low, any_receiver=not direct_this)
                        margs = None
                        if lst:
                            margs = _split_args(stmt, i + 1)[0]
                            self._via_wrapper(low, margs, env, t, lst, origin)
                        if low in self.setters and (direct_this or self.defcount.get(low) == 1):
                            margs = margs if margs is not None else _split_args(stmt, i + 1)[0]
                            for pi, prop, kind in self.setters[low]:
                                if pi < len(margs) and kind in self._taint(margs[pi], env):
                                    self.props[prop] = self.props.get(prop, frozenset()) | {kind}
                    continue
                fname = _lname(t[1])
                args, close = _split_args(stmt, i + 1)
                specs = _FN_SINKS.get(fname)
                if specs:
                    for s in specs:
                        if self._fire(s, fname, args, env, t):
                            break
                lst, origin = self._wraps(fname)
                if lst:
                    self._via_wrapper(fname, args, env, t, lst, origin)
                if fname == "move_uploaded_file" and len(args) >= 2 and "upname" in self._taint(args[1], env):
                    cand = (t, self.fstart[-1])
                    if cand not in self.uploads:
                        self.uploads.append(cand)
                self._call_patterns(fname, args, stmt, i, close, env, t)
            elif typ == "var" and i + 1 < n and _isop(stmt[i + 1], "(") and \
                    not (i and stmt[i - 1][0] == "op" and stmt[i - 1][1] in ("->", "::", "$")):
                if "code" in env.get(t[1], NONE) or t[1] in SUPERGLOBALS:
                    self.add("variable-function-tainted", t)
            elif typ == "var" and i + 2 < n and _isop(stmt[i + 1], "[") and not i:
                pass
            elif typ == "op" and t[1] == "$" and i + 1 < n:
                nxt = stmt[i + 1]
                if nxt[0] == "var":
                    tt, _ = self._var_taint(stmt, i + 1, env)
                elif _isop(nxt, "{"):
                    tt = self._taint(stmt[i + 2:_match_close(stmt, i + 1)], env)
                else:
                    tt = set()
                if _real(tt):
                    self.add("variable-variable-tainted", t)

    def _via_wrapper(self, name, args, env, tok, lst=None, origin=None):
        """A function that passes its argument to a sink (here or in another file),
        called with request data. Called with one of our own parameters instead,
        it makes the current function a wrapper too (a wrapper of a wrapper)."""
        where = " in %s" % origin if origin else ""
        cur = self.fn_stack[-1]
        for pi, kind, rid, sink in (lst if lst is not None else self.wrappers.get(name, ())):
            if pi >= len(args):
                continue
            t = self._taint(args[pi], env)
            if kind in t:
                self.add(rid, tok, "%s: request data reaches %s() via %s()%s (argument %d)."
                         % (RULES_BY_ID[rid]["title"], sink, name, where, pi + 1))
            elif self.pass_no == 1 and cur and cur != name:
                for x in t:
                    if x.startswith(kind + "@"):
                        w = (int(x.rsplit("@", 1)[1]), kind, rid, sink)
                        wl = self.wrappers.setdefault(cur, [])
                        if w not in wl:
                            wl.append(w)

    def _method_sink(self, stmt, i, env):
        meth = stmt[i][1].lower()
        specs = _METH_SINKS.get(meth)
        if not specs:
            return
        if self.ext and meth in self.ext["uniq"] and (meth in self.ext["wrap"] or meth in self.wrappers):
            return    # the project's own method of that name: its summary decides, not a library guess
        recv_t = stmt[i - 2] if i >= 2 else None
        recv = recv_t[1].lstrip("$") if recv_t is not None and recv_t[0] in ("var", "id") else ""
        args, _ = _split_args(stmt, i + 1)
        for s in specs:
            rx = s.get("receiver")
            if rx:
                r = _RECV_RE.get(rx) or _RECV_RE.setdefault(rx, re.compile(rx))
                if not recv or not r.search(recv):
                    continue
                if s["rule"] in ("sql-db-query", "sql-prepare-tainted") and recv.lower() == "wpdb" and meth != "prepare":
                    continue
            if self._fire(s, meth, args, env, stmt[i]):
                return
            if rx:
                return  # first receiver-matching spec owns the call

    def _call_patterns(self, fname, args, stmt, i, close, env, tok):
        if fname == "eval" and args:
            a = _strip_parens(args[0])
            if a and a[0][0] == "id" and _lname(a[0][1]) in ("base64_decode", "gzinflate", "gzuncompress",
                                                             "str_rot13", "gzdecode", "hex2bin", "convert_uudecode"):
                self.add("eval-encoded-payload", tok)
        elif fname == "create_function":
            self.add("create-function", tok)
        elif fname in ("preg_replace", "preg_filter") and args:
            lit = _literal_str(args[0])
            if lit and len(lit) > 2 and not lit[0].isalnum() and lit[0] not in "\\ ":
                d = {"(": ")", "[": "]", "{": "}", "<": ">"}.get(lit[0], lit[0])
                end = lit.rfind(d)
                if end > 0 and "e" in lit[end + 1:]:
                    self.add("preg-replace-e", tok)
        elif fname in ("unserialize", "maybe_unserialize") and args:
            a0 = _strip_parens(args[0])
            if a0 and a0[0][0] == "id" and a0[0][1].lower() == "serialize":
                pass  # unserialize(serialize($x)) deep-clone idiom
            elif len(args) == 1 and fname == "unserialize" and _literal_str(args[0]) is None \
                    and "deser" not in self._taint(args[0], env):
                self.add("unserialize-no-allowed-classes", tok)
        elif fname in ("md5", "sha1") and args or fname == "hash" and len(args) >= 2 and \
                (_literal_str(args[0]) or "").lower() in ("md5", "sha1"):
            a = args[0] if fname != "hash" else args[1]
            names = [t[1] for t in a if t[0] == "var"] + \
                    [a[k + 1][1] for k in range(len(a) - 1) if _isop(a[k], "->") and a[k + 1][0] == "id"] + \
                    [t[1] for t in a if t[0] == "str" and len(a) > 1]
            if any(PASSWORD_VAR.search(x) for x in names):
                self.add("weak-hash-password", tok)
        elif fname == "crypt" and len(args) == 1:
            self.add("crypt-no-salt", tok)
        elif fname in ("openssl_encrypt", "openssl_decrypt") and len(args) >= 2:
            m = _literal_str(args[1]) or ""
            if re.search(r"(?i)(-ecb$|^ecb$|-ecb-)", m) or m.lower() in ("des-ede3", "aes-128", "aes-256"):
                self.add("openssl-ecb", tok)
        elif fname.startswith("mcrypt_"):
            self.add("mcrypt-deprecated", tok)
        elif fname in ("ini_set", "ini_alter") and len(args) >= 2:
            key = (_literal_str(args[0]) or "").lower()
            v = _strip_parens(args[1])
            on = len(v) == 1 and (v[0][0] in ("num",) and v[0][1] != "0" or
                                  v[0][0] == "str" and v[0][1].lower() in ("1", "on", "true", "stdout", "yes") or
                                  v[0][0] == "id" and v[0][1].lower() == "true")
            off = len(v) == 1 and (v[0][1] == "0" or v[0][0] == "str" and v[0][1].lower() in ("0", "off", "false", "") or
                                   v[0][0] == "id" and v[0][1].lower() == "false")
            if key == "display_errors" and on:
                self.add("display-errors-on", tok)
            elif key == "allow_url_include" and on:
                self.add("allow-url-include", tok)
            elif key in ("session.cookie_httponly", "session.cookie_secure") and off:
                self.add("session-cookie-insecure-ini", tok)
        elif fname == "phpinfo":
            self.add("phpinfo-call", tok)
        elif fname == "extract" and args:
            a = _strip_parens(args[0])
            if a and a[0][0] == "var" and a[0][1] in ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER") \
                    and len(a) == 1:
                self.add("extract-superglobal", tok)
        elif fname in ("parse_str", "mb_parse_str") and len(args) == 1:
            self.add("parse-str-one-arg", tok)
        elif fname == "libxml_disable_entity_loader" and args:
            v = _strip_parens(args[0])
            if len(v) == 1 and (v[0][1].lower() == "false" or v[0][1] == "0"):
                self.add("xxe-entity-loader", tok)
        elif fname == "header" and args:
            a = _strip_parens(args[0])
            if a and a[0][0] in ("str", "dstr") and a[0][1].lower().replace(" ", "").startswith("location:"):
                t = self._taint(a, env)
                if "redirect" in t:
                    self.add("redirect-header", tok)
        elif fname == "curl_setopt" and len(args) >= 3:
            opt = _strip_parens(args[1])
            if len(opt) == 1 and opt[0][1] == "CURLOPT_URL" and "url" in self._taint(args[2], env):
                self.add("ssrf-curl", tok)
        elif fname in ("setcookie", "setrawcookie") and args:
            name = _literal_str(args[0])
            if name and SESSIONISH.search(name):
                if len(args) == 3 and _strip_parens(args[2])[:1] and _strip_parens(args[2])[0][0] == "op" \
                        and _strip_parens(args[2])[0][1] == "[" or len(args) == 3 and args[2] and \
                        args[2][0][0] == "id" and args[2][0][1].lower() == "array":
                    flat = {t[1].lower() for t in args[2] if t[0] == "str"}
                    if not ("secure" in flat and "httponly" in flat):
                        self.add("cookie-insecure", tok)
                elif len(args) == 3 and args[2] and args[2][0][0] == "var":
                    pass  # options array built elsewhere
                else:
                    def truthy(k):
                        if k >= len(args):
                            return False
                        v = _strip_parens(args[k])
                        return not (len(v) == 1 and (v[0][1].lower() in ("false", "null") or v[0][1] == "0"))
                    if not (truthy(5) and truthy(6)):
                        self.add("cookie-insecure", tok)
        elif fname == "define" and len(args) >= 2:
            k, v = _literal_str(args[0]), _strip_parens(args[1])
            if k and len(v) == 1 and v[0][0] == "str":
                self._secret(k, v[0], tok)
        elif fname == "add_action" and args:
            hook = _literal_str(args[0])
            if hook and hook.startswith("wp_ajax_") and len(args) >= 2:
                cb = self._callback_name(args[1])
                if cb:
                    self.hooks.append(("nopriv" if hook.startswith("wp_ajax_nopriv_") else "priv", cb, tok))
        elif fname == "register_rest_route" and len(args) >= 3:
            flat = [t for a in args[2:] for t in a]
            for k, t in enumerate(flat):
                if t[0] == "str" and t[1] == "permission_callback" and k + 2 < len(flat) and \
                        _isop(flat[k + 1], "=>") and flat[k + 2][0] == "str" and flat[k + 2][1] == "__return_true":
                    for k2, t2 in enumerate(flat):
                        if t2[0] == "str" and t2[1] == "callback" and k2 + 2 < len(flat) and _isop(flat[k2 + 1], "=>"):
                            end = k2 + 2
                            depth = 0
                            seg = []
                            while end < len(flat):
                                x = flat[end]
                                if x[0] == "op" and x[1] in "([":
                                    depth += 1
                                elif x[0] == "op" and x[1] in ")]":
                                    depth -= 1
                                    if depth < 0:
                                        break
                                elif _isop(x, ",") and depth == 0:
                                    break
                                seg.append(x)
                                end += 1
                            cb = self._callback_name(seg)
                            if cb:
                                self.rest.append((cb, tok))
                            break
                    break

    @staticmethod
    def _callback_name(arg):
        strs = [t[1] for t in arg if t[0] == "str"]
        if strs:
            return strs[-1].split("::")[-1].lower()
        return None

    def _secret(self, name, strtok, tok):
        val = strtok[1]
        norm = re.sub(r"([a-z])([A-Z])", r"\1_\2", name.lstrip("$")).lower()
        if not SECRET_NAME.search(norm):
            return
        if _PEM.search(val):
            return
        if len(val) < 8 or re.search(r"\s|\|", val) or SECRET_PLACEHOLDER.search(val):
            return
        if re.fullmatch(r"[a-z_.\-:/]+", val) or re.fullmatch(r"[A-Z_]+", val) or len(set(val)) < 4:
            return
        if re.fullmatch(r"[\w\-]+\.[\w\-]+", val) and not re.search(r"\d", val):
            return
        self.add("hardcoded-secret", tok)

    def _patterns(self, stmt, env):
        n = len(stmt)
        # secrets / weak random on assignment
        t0 = stmt[0]
        for k, t in enumerate(stmt):
            if t[0] == "str":
                if _PEM.search(t[1]):
                    self.add("hardcoded-private-key", t)
                elif _AWS.search(t[1]):
                    self.add("hardcoded-aws-key", t)
            elif t[0] == "dstr" and _PEM.search(t[1]):
                self.add("hardcoded-private-key", t)
            if t[0] == "str" and k + 2 < n and _isop(stmt[k + 1], "=>"):
                v = stmt[k + 2]
                tail_ok = k + 3 >= n or stmt[k + 3][0] == "op" and stmt[k + 3][1] in (",", ")", "]")
                if v[0] == "str" and tail_ok:
                    self._secret(t[1], v, v)
                if v[0] == "id" and k + 3 < n and _isop(stmt[k + 3], "(") and _lname(v[1]) in WEAK_RAND \
                        and SECRET_VAR.search(t[1]):
                    self.add("weak-random-secret", v)
                if (t[1] in ("verify", "verify_peer", "verify_peer_name", "sslverify")) \
                        and v[0] == "id" and v[1].lower() in ("false", "true"):
                    bad = v[1].lower() == ("true" if t[1] == "allow_self_signed" else "false")
                    if bad and tail_ok and not self.tls_opt and not self.tls_tmp:
                        self.add("tls-verify-disabled", v)
            if t[0] == "id" and t[1] in ("CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST") and k + 2 < n \
                    and stmt[k + 1][0] == "op" and stmt[k + 1][1] in (",", "=>"):
                v = stmt[k + 2]
                if (v[1].lower() == "false" or v[1] == "0") and (k + 3 >= n or stmt[k + 3][0] == "op" and stmt[k + 3][1] in (",", ")", "]")) \
                        and not self.tls_opt and not self.tls_tmp:
                    self.add("tls-verify-disabled", t)
            if t[0] == "id" and t[1] == "LIBXML_NOENT":
                self.add("xxe-noent", t)
            if t[0] == "id" and t[1] == "SUBST_ENTITIES" and k + 2 < n and _isop(stmt[k + 1], ","):
                if stmt[k + 2][1].lower() in ("true", "1"):
                    self.add("xxe-xmlreader-subst", t)
        # $x = 'literal'; / property / const
        j = 0
        while j < n and stmt[j][0] == "id" and stmt[j][1].lower() in (
                "public", "private", "protected", "static", "var", "readonly", "const", "final", "global"):
            j += 1
        if j + 2 < n + 0 and j + 2 == n - 1 and _isop(stmt[j + 1], "=") and stmt[j + 2][0] == "str" and \
                stmt[j][0] in ("var", "id"):
            self._secret(stmt[j][1], stmt[j + 2], stmt[j])
        elif j + 3 == n - 1 and stmt[j][0] == "id" and stmt[j + 1][0] == "id" and _isop(stmt[j + 2], "=") \
                and stmt[j + 3][0] == "str":  # typed property / const
            self._secret(stmt[j + 1][1], stmt[j + 3], stmt[j + 1])
        # weak random assigned to secret-like var
        if j < n and stmt[j][0] == "var":
            vj = self._skip_var(stmt, j)
            name = stmt[vj - 1][1] if 0 < vj <= n else ""
            if vj < n and _isop(stmt[vj], "=") and SECRET_VAR.search(name.lstrip("$")):
                rhs = stmt[vj + 1:]
                for k, t in enumerate(rhs):
                    if t[0] == "id" and _lname(t[1]) in WEAK_RAND and k + 1 < len(rhs) and _isop(rhs[k + 1], "("):
                        if not any(x[0] == "id" and _lname(x[1]) in ("random_bytes", "random_int", "openssl_random_pseudo_bytes",
                                                                       "wp_generate_password", "bin2hex")
                                   for x in rhs):
                            self.add("weak-random-secret", t)
                        break
            # $guarded = [];
            if self.is_model and name == "$guarded" and vj < n and _isop(stmt[vj], "="):
                rhs = stmt[vj + 1:]
                if [x[1] for x in rhs] in (["[", "]"], ["array", "(", ")"]):
                    self.add("laravel-guarded-empty", stmt[vj - 1])


# ---------------------------------------------------------------------------
def _walk(root, include_tests):
    php, envs = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and
                             (include_tests or d.lower() not in TEST_DIRS))
        for f in sorted(filenames):
            if f.endswith(PHP_EXTS):
                if not include_tests and re.search(r"Test\.php$", f):
                    continue
                php.append(os.path.join(dirpath, f))
            elif f == ".env" or (f.startswith(".env.") and not re.search(
                    r"(example|sample|dist|template|testing|test|local|ci)$", f)):
                envs.append(os.path.join(dirpath, f))
        if len(php) >= MAX_FILES:
            break
    return php[:MAX_FILES], envs


def _gitignored_env(root):
    try:
        with open(os.path.join(root, ".gitignore"), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s in (".env", "/.env", ".env*", "/.env*", "*.env", ".env.*"):
                    return True
    except OSError:
        pass
    return False


def _lock_packages(root, lock_findings):
    names = set()
    try:
        with open(os.path.join(root, "composer.lock"), encoding="utf-8") as fh:
            data = json.load(fh)
        for key in ("packages", "packages-dev"):
            for p in data.get(key) or []:
                if isinstance(p, dict) and p.get("name"):
                    names.add(p["name"].lower())
    except (OSError, ValueError):
        pass
    exploited = {}
    for lf in lock_findings or []:
        get = lf.get if isinstance(lf, dict) else (lambda k, d=None, _o=lf: getattr(_o, k, d))
        pkg = (get("package") or "")
        pkg = pkg.lower() if isinstance(pkg, str) else ""
        if pkg:
            names.add(pkg)
            if get("known_exploited"):
                exploited.setdefault(pkg, []).append(get("cve") or "")
    gadgets = sorted(n for n in names if any(n == g or (g.endswith("/") and n.startswith(g)) for g in GADGET_PACKAGES))
    return gadgets, exploited


def _bump(sev):
    i = SEV_RANK.get(sev, 3)
    return SEVERITIES[max(0, i - 1)]


_DIR_TOKENS = {"__dir__"}


def _make_resolver(files):
    """Resolve `include <expr>` to a project file when the path is a literal, or
    a literal joined to __DIR__, dirname(__FILE__) or a constant. Anything with
    a variable in it is left alone."""
    def resolve(rel, toks):
        toks = _strip_parens(toks)
        lits, base_dir, unknown_const = [], False, False
        k, n = 0, len(toks)
        while k < n:
            t = toks[k]
            if t[0] in ("str", "dstr"):
                if t[0] == "dstr" and "$" in t[1]:
                    return None
                lits.append(t[1])
            elif t[0] == "id" and t[1].lower() in _DIR_TOKENS:
                base_dir = True
            elif t[0] == "id" and t[1].lower() == "dirname" and k + 1 < n and _isop(toks[k + 1], "("):
                close = _match_close(toks, k + 1)
                if not any(x[0] == "id" and x[1] in ("__FILE__", "__DIR__") for x in toks[k + 2:close]):
                    return None
                base_dir = True
                k = close
            elif t[0] == "id" and re.fullmatch(r"[A-Z_][A-Z0-9_]*", t[1]):
                unknown_const = True
            elif _isop(t, "."):
                pass
            else:
                return None
            k += 1
        if not lits:
            return None
        lit = "".join(lits)
        here = posixpath.dirname(rel)
        cands = [posixpath.join(here, lit.lstrip("/"))] if base_dir else \
            [posixpath.join(here, lit), lit.lstrip("/")] + ([posixpath.join(here, lit.lstrip("/"))] if unknown_const else [])
        for c in cands:
            c = posixpath.normpath(c)
            if c in files:
                return c
        return None
    return resolve


def _scan_file(fp, rel, enabled, ext=None, seed=None):
    try:
        with open(fp, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return None
    try:
        return FileScanner(src, rel, enabled, ext, seed).run()
    except Exception:  # never let one odd file abort the scan
        return None


def _summary_of(fs):
    """What other files need from one scanned file; the token stream is dropped."""
    return {"wrap": {k: list(v) for k, v in fs.wrappers.items()},
            # other files see a function as "returns request data" only when every
            # return in it does; one path among several is too weak a claim to export
            # (and only for direct request input, not the current URL from $_SERVER)
            "tret": {k: frozenset(v) for k, v in fs.tret.items()
                     if "src" in v and fs.ret_seen.get(k) and fs.ret_hit.get(k, set()) >= fs.ret_seen[k]},
            "retp": {k: dict(v) for k, v in fs.retp.items()},
            "defcount": fs.defcount, "calls": fs.calls, "exports": fs.exports,
            "snap": fs.incl_snap, "targets": fs.incl_targets,
            "info": {k: "%s:%d" % (v["file"], v["line"]) for k, v in fs.funcs.items()},
            "funcs": fs.funcs, "fcalls": fs.fcalls, "has_source": fs.has_source}


def _build_ext(sums, resolve):
    """Merge per-file summaries into the tables a FileScanner reads (`ext`)."""
    defs, per_name = {}, {}
    for rel, sm in sums.items():
        for name, c in sm["defcount"].items():
            defs[name] = defs.get(name, 0) + c
            per_name.setdefault(name, []).append(rel)
    wrap, tret, retp, info, uniq = {}, {}, {}, {}, set()
    for name, rels in per_name.items():
        if defs[name] == 1:
            uniq.add(name)
        elif len(rels) == defs[name]:
            # several definitions (one per file): usable only when they all agree
            keys = {(repr(sorted(sums[r]["wrap"].get(name, []))), repr(sorted(sums[r]["tret"].get(name, ()))),
                     repr(sorted((p, sorted(k)) for p, k in sums[r]["retp"].get(name, {}).items()))) for r in rels}
            if len(keys) == 1:
                uniq.add(name)
        if name not in uniq:
            continue
        r0 = rels[0]
        if sums[r0]["wrap"].get(name):
            wrap[name] = sums[r0]["wrap"][name]
        if sums[r0]["tret"].get(name):
            tret[name] = sums[r0]["tret"][name]
        if sums[r0]["retp"].get(name):
            retp[name] = sums[r0]["retp"][name]
        if name in sums[r0]["info"]:
            info[name] = sums[r0]["info"][name]
    exports = {rel: sm["exports"] for rel, sm in sums.items() if sm["exports"]}
    seeds = {}
    for rel, sm in sums.items():
        for target, snap in sm["snap"].items():
            cur = seeds.setdefault(target, {})
            for k, v in snap.items():
                cur[k] = cur.get(k, frozenset()) | v
    return {"wrap": wrap, "tret": tret, "retp": retp, "info": info, "uniq": uniq,
            "exports": exports, "resolve": resolve}, seeds


def scan_project(path, *, include_tests=False, lock_findings=None, rules=None, all_rules=False):
    """rules: only these rule ids. all_rules: also run the opt-in rules that are
    off by default because they are noisy (see list_rules(): "default": false).

    Two stages. Every file is scanned on its own first. Then, for up to
    MAX_ROUNDS rounds, files are scanned again with what the other files export:
    functions and methods that pass a parameter to a sink (wrappers), that
    return request data, or that pass a parameter through to their return value;
    and file-level variables shared through literal includes. Only names defined
    once in the project (or identically everywhere) are used."""
    root = os.path.abspath(path)
    enabled = set(rules) if rules else {r["id"] for r in RULES if all_rules or r.get("default", True)}
    files, envs = _walk(root, include_tests) if os.path.isdir(root) else ([root], [])
    todo = []
    total = 0
    for fp in files:
        try:
            size = os.path.getsize(fp)
        except OSError:
            continue
        if size > MAX_FILE:
            continue
        if total + size > MAX_TOTAL:
            break
        total += size
        rel = os.path.relpath(fp, root) if os.path.isdir(root) else os.path.basename(fp)
        todo.append((fp, rel.replace(os.sep, "/")))
    by_rel = {rel: fp for fp, rel in todo}
    resolve = _make_resolver(set(by_rel))
    sums, per_file, keep = {}, {}, {}
    for fp, rel in todo:
        fs = _scan_file(fp, rel, enabled, {"wrap": {}, "tret": {}, "retp": {}, "info": {}, "uniq": set(),
                                            "exports": {}, "resolve": resolve} if len(todo) > 1 else None)
        if fs is None:
            continue
        sums[rel] = _summary_of(fs)
        per_file[rel] = fs.findings
        if fs.hooks or fs.rest:
            keep[rel] = fs
    # project-wide rounds
    prev_ext = {"wrap": {}, "tret": {}, "retp": {}, "uniq": set()}
    prev_exports, prev_seeds = {}, {}
    for _round in range(MAX_ROUNDS if len(sums) > 1 else 0):
        ext, seeds = _build_ext(sums, resolve)
        changed = set()
        # pass-through summaries (retp) are many and only matter one level deep
        # across files: they trigger rescans in the first round only
        for table in (("wrap", "tret", "retp") if _round == 0 else ("wrap", "tret")):
            for name in set(ext[table]) | set(prev_ext[table]):
                if (ext[table].get(name) != prev_ext[table].get(name)) or \
                        ((name in ext["uniq"]) != (name in prev_ext["uniq"]) and (name in ext[table] or name in prev_ext[table])):
                    changed.add(name)
        changed_exports = {r for r in set(ext["exports"]) | set(prev_exports)
                           if ext["exports"].get(r) != prev_exports.get(r)}
        # The including file's variables are not pushed into the included file:
        # names are reused too freely between templates for that to be precise.
        changed_seeds = set()
        ext_tret = set(ext["tret"])
        redo = []
        for rel, sm in sums.items():
            hits = changed & (sm["calls"] - set(sm["defcount"]))
            if not hits and not (changed_exports & sm["targets"]) and rel not in changed_seeds:
                continue
            # rescan when it can change something: a finding here (the file has
            # request input, or calls a function that returns it) or a summary of a
            # function defined here (it calls the changed name)
            if (changed_exports & sm["targets"]) or rel in changed_seeds or \
                    (hits and (sm["has_source"] or (sm["calls"] & ext_tret))) or (hits & sm["fcalls"]):
                redo.append(rel)
        if not redo:
            break
        for rel in redo:
            fs = _scan_file(by_rel[rel], rel, enabled, ext)
            if fs is None:
                continue
            sums[rel] = _summary_of(fs)
            per_file[rel] = fs.findings
            if fs.hooks or fs.rest:
                keep[rel] = fs
        prev_ext, prev_exports, prev_seeds = ext, ext["exports"], seeds
    findings, funcs, hooks, rests = [], {}, [], []
    scanned = len(sums)
    for rel in sums:                      # file order, as before
        findings.extend(per_file[rel].values())
        funcs.update(sums[rel]["funcs"])
    for rel, fs in keep.items():
        hooks.extend((h, fs) for h in fs.hooks)
        rests.extend((r, fs) for r in fs.rest)
    # WordPress handler resolution (project-wide)
    nopriv = {cb for (typ, cb, _), _fs in hooks if typ == "nopriv"}
    for (typ, cb, tok), fs in hooks:
        info = funcs.get(cb)
        if not info or not info["writes"]:
            continue
        before = len(fs.findings)
        if typ == "nopriv" and not info["guards"]:
            fs.add("wp-nopriv-ajax-no-auth", tok, "wp_ajax_nopriv_ handler %s() (%s:%d) writes without nonce/capability check."
                   % (cb, info["file"], info["line"]))
        elif typ == "priv" and cb not in nopriv and not info["nonce"]:
            fs.add("wp-ajax-no-nonce", tok, "AJAX handler %s() (%s:%d) writes without a nonce check."
                   % (cb, info["file"], info["line"]))
        if len(fs.findings) > before:
            findings.append(list(fs.findings.values())[-1])
    for (cb, tok), fs in rests:
        info = funcs.get(cb)
        if info and info["writes"]:
            before = len(fs.findings)
            fs.add("wp-rest-open-write", tok, "REST callback %s() (%s:%d) writes but permission_callback is __return_true."
                   % (cb, info["file"], info["line"]))
            if len(fs.findings) > before:
                findings.append(list(fs.findings.values())[-1])
    # Laravel .env
    if envs and "laravel-app-debug-env" in enabled and not _gitignored_env(root):
        for ep in envs:
            try:
                with open(ep, encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            for ln, line in enumerate(lines, 1):
                if re.match(r"^\s*APP_DEBUG\s*=\s*[\"']?(true|1|on)[\"']?\s*$", line, re.I):
                    r = RULES_BY_ID["laravel-app-debug-env"]
                    findings.append({"rule": r["id"], "title": r["title"], "severity": r["severity"], "cwe": r["cwe"],
                                     "file": os.path.relpath(ep, root).replace(os.sep, "/"), "line": ln, "column": 1,
                                     "snippet": line.strip()[:200], "message": r["description"], "fix": r["fix"],
                                     "context": []})
    # gadget-chain context boost
    gadgets, exploited = _lock_packages(root, lock_findings) if os.path.isdir(root) else ([], {})
    if gadgets:
        for f in findings:
            if f["rule"] in ("unserialize-tainted", "unserialize-no-allowed-classes"):
                f["context"] = ["gadget-chain: %s" % g for g in gadgets] + \
                               ["known-exploited: %s %s" % (p, c) for p, cs in exploited.items() if p in gadgets for c in cs]
                f["severity"] = _bump(f["severity"])
                f["message"] += " A dependency with a known gadget chain is installed (%s)." % ", ".join(gadgets)
    findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["file"], f["line"], f["column"], f["rule"]))
    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    return {"tool": "phpwarden-code", "version": _VERSION, "root": root, "files_scanned": scanned,
            "findings": findings, "summary": summary}


def list_rules():
    return [dict(r) for r in RULES]


def exit_code(result):
    return 1 if any(f["severity"] in ("critical", "high") for f in result.get("findings", [])) else 0


def to_text(result):
    out = ["phpwarden code %s -- %s (%d files scanned)" % (result["version"], result["root"], result["files_scanned"])]
    if not result["findings"]:
        out.append("No findings.")
    for f in result["findings"]:
        out.append("")
        out.append("[%s] %s  %s:%d:%d  (%s, %s)" % (f["severity"].upper(), f["title"], f["file"], f["line"],
                                                  f["column"], f["rule"], f["cwe"]))
        out.append("    " + f["snippet"])
        for c in f.get("context") or []:
            out.append("    context: " + c)
        out.append("    fix: " + f["fix"])
    s = result["summary"]
    out.append("")
    out.append("Summary: " + ", ".join("%d %s" % (s.get(k, 0), k) for k in SEVERITIES))
    return "\n".join(out)


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SEC_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def to_sarif(result):
    rules = []
    index = {}
    for i, r in enumerate(RULES):
        index[r["id"]] = i
        rules.append({"id": r["id"], "name": r["id"].replace("-", "_"),
                      "shortDescription": {"text": r["title"]},
                      "fullDescription": {"text": r["description"]},
                      "help": {"text": r["fix"]},
                      "defaultConfiguration": {"level": _SARIF_LEVEL[r["severity"]]},
                      "properties": {"tags": ["security", r["category"], r["cwe"]],
                                     "security-severity": _SEC_SCORE[r["severity"]]}})
    results = []
    for f in result["findings"]:
        results.append({"ruleId": f["rule"], "ruleIndex": index.get(f["rule"], 0),
                        "level": _SARIF_LEVEL.get(f["severity"], "warning"),
                        "message": {"text": f["message"] + (" [" + "; ".join(f["context"]) + "]" if f.get("context") else "")},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": f["file"], "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": f["line"], "startColumn": f["column"],
                                       "snippet": {"text": f["snippet"]}}}}],
                        "properties": {"severity": f["severity"], "cwe": f["cwe"], "context": f.get("context") or []}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "phpwarden-code", "version": result["version"],
                                          "informationUri": "https://phpwarden.io", "rules": rules}},
                      "originalUriBaseIds": {"%SRCROOT%": {"uri": "file://" + result["root"].rstrip("/") + "/"}},
                      "results": results}]}
