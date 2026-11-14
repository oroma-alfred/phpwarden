"""PHP core library model: sources, sinks, sanitizers and propagators.

The vocabularies are shared with the token engine (phpwarden/code.py) so both
engines agree on what is dangerous and what makes a value safe. A taint value
carries the set of sink kinds it is still dangerous for:

    sql xss cmd path incl code url redirect deser ldap xpath session env
    hdr   mail header injection (new with the AST engine)
    mass  the whole request bag ($request->all()), for mass-assignment
    sqlq  went through an SQL string escaper: safe inside quotes only
"""
from __future__ import annotations

import re

from phpwarden import code as _code
from phpwarden.code_rules import TAINT_SINKS

ALL = frozenset(_code.ALL | {"hdr"})
SOURCE_KINDS = ALL
SUPERGLOBALS = frozenset(x.lstrip("$") for x in _code.SUPERGLOBALS)
SERVER_KEYS = frozenset(_code.SERVER_KEYS)
FILES_SAFE_KEYS = frozenset(_code.FILES_SAFE_KEYS)

GUARD_FNS = frozenset(_code.GUARD_FNS)
EXIT_FNS = frozenset(_code.EXIT_KW) - {"return", "throw", "continue", "break"}
VALIDATORS = frozenset(_code.VALIDATORS)
STATEMENT_GUARDS = dict(_code.STATEMENT_GUARDS)
SQL_ESCAPERS = frozenset(_code.SQL_ESCAPERS)
SQL_ESCAPE_METHODS = frozenset(_code.SQL_ESCAPE_METHODS)
FILTER_SAFE = _code.FILTER_SAFE
FILTER_XSS = _code.FILTER_XSS
INT_CASTS = frozenset(_code.INT_CASTS)
whitelist_pattern = _code._whitelist_pattern
negclass_pattern = _code._negclass_pattern

# Functions that make a value safe for some sink kinds. A value of ALLX in the
# token engine means "clears everything" (numbers, hashes, booleans).
_CLEAR_ALL = object()
SANITIZERS = {}
for _f, _kinds in _code.SANITIZERS.items():
    SANITIZERS[_f] = _CLEAR_ALL if _kinds >= _code.ALL else frozenset(_kinds)
SANITIZERS.update({
    "intdiv": _CLEAR_ALL, "array_keys": frozenset(), "array_key_first": frozenset(),
    "filter_var": None,          # decided by the filter argument (see sanitize_call)
    "esc_html_e": frozenset({"xss"}), "esc_attr_e": frozenset({"xss"}),
    "wp_kses_allowed_html": _CLEAR_ALL, "sanitize_email": frozenset({"xss", "sql", "cmd", "hdr"}),
    "is_email": _CLEAR_ALL, "wp_validate_boolean": _CLEAR_ALL, "rest_sanitize_boolean": _CLEAR_ALL,
    "sanitize_hex_color": _CLEAR_ALL, "sanitize_html_class": frozenset({"xss", "sql", "cmd", "path", "incl"}),
    "sanitize_mime_type": frozenset({"xss", "hdr"}), "sanitize_sql_orderby": frozenset({"sql"}),
    "str_contains": _CLEAR_ALL, "str_starts_with": _CLEAR_ALL, "str_ends_with": _CLEAR_ALL,
    "strcmp": _CLEAR_ALL, "strcasecmp": _CLEAR_ALL, "version_compare": _CLEAR_ALL, "hash_equals": _CLEAR_ALL,
    "array_search": _CLEAR_ALL, "ip2long": _CLEAR_ALL, "inet_pton": _CLEAR_ALL, "random_int": _CLEAR_ALL,
    "str_word_count": _CLEAR_ALL, "substr_count": _CLEAR_ALL, "array_key_last": frozenset(),
    "uuid_is_valid": _CLEAR_ALL, "ctype_alpha": _CLEAR_ALL, "ctype_xdigit": _CLEAR_ALL,
    "escapeshellarg": frozenset({"cmd"}), "escapeshellcmd": frozenset({"cmd"}),
    "htmlspecialchars": frozenset({"xss"}), "htmlentities": frozenset({"xss"}),
    "str_replace_crlf": frozenset({"hdr"}),
    # WordPress upload handlers return the file moved to a sanitized, unique
    # name under the uploads directory (and its URL and checked type)
    "wp_handle_upload": frozenset({"path", "incl", "cmd", "sql", "url", "redirect", "deser", "code"}),
    "_wp_handle_upload": frozenset({"path", "incl", "cmd", "sql", "url", "redirect", "deser", "code"}),
    "wp_handle_sideload": frozenset({"path", "incl", "cmd", "sql", "url", "redirect", "deser", "code"}),
    "media_handle_upload": _CLEAR_ALL, "media_handle_sideload": _CLEAR_ALL,
    "sanitize_file_name": frozenset({"path", "incl", "cmd"}),
    "wp_unique_filename": frozenset({"path", "incl", "cmd"}),
})
# Methods whose return value is built by the framework, not taken from the
# request: Laravel UploadedFile::hashName() (random name), Symfony
# guessExtension() (from the detected MIME type). getClientOriginalName() and
# getClientOriginalExtension() are request data and are NOT here.
SAFE_RETURN_METHODS = frozenset({"hashname", "guessextension", "getmimetype", "getsize", "geterror"})
CLEAR_ALL = _CLEAR_ALL

PROPAGATORS = frozenset(_code.PROPAGATORS) | {
    "sprintf", "vsprintf", "implode", "join", "array_merge", "array_merge_recursive", "array_replace",
    "array_values", "array_unique", "array_reverse", "array_column", "array_combine", "array_fill_keys",
    "array_pad", "array_chunk", "array_flip", "mb_strtolower", "mb_strtoupper", "nl2br", "wordwrap",
    "str_split", "mb_str_split", "chunk_split", "quotemeta", "addcslashes", "money_format", "number_format_i18n",
    "strip_shortcodes", "wp_trim_words", "wp_strip_all_tags", "maybe_serialize", "serialize", "var_export",
    "print_r", "json_decode", "unserialize", "maybe_unserialize", "base64_encode", "urldecode", "trim",
    "array_map_recursive", "array_filter", "array_slice", "array_splice", "end", "next", "prev", "key",
    "array_pop", "array_shift", "current", "reset", "strval", "settype", "str_word", "ucwords", "lcfirst",
    "preg_replace", "preg_split", "preg_quote", "mb_substr", "substr", "strstr", "stristr", "strrchr",
    "html_entity_decode", "htmlspecialchars_decode", "wp_unslash", "stripslashes", "stripslashes_deep",
    "sanitize_option",
}
# Propagators that keep the "whole request" marker (mass assignment).
MASS_KEEPERS = frozenset({"array_merge", "array_merge_recursive", "array_replace", "wp_unslash",
                          "stripslashes_deep", "array_filter"})

# Sinks: the token engine's table, interpreted on the AST, plus sinks that
# need the AST (constructors, chains, templates). See models/__init__.py.
SINKS = [dict(s) for s in TAINT_SINKS]
SINKS += [
    {"rule": "mail-header-injection", "fn": ["mail"], "args": [3], "taint": "hdr"},
    {"rule": "mail-header-injection", "fn": ["wp_mail"], "args": [3], "taint": "hdr"},
    {"rule": "sql-db-query", "method": ["query", "exec", "multi_query", "real_query", "prepare"],
     "classes": ["pdo", "mysqli"], "args": [0], "taint": "sql"},
    {"rule": "cmd-proc-open", "fn": ["proc_open"], "args": [0], "taint": "cmd"},
    {"rule": "path-read", "fn": ["fread", "gzopen", "readgzfile", "file_get_contents", "md5_file", "sha1_file"],
     "args": [0], "taint": "path"},
]

# Statement-level sinks (echo/print/include/eval/backticks/exit) are handled by
# the walker directly; their rule ids:
ECHO_RULE = "xss-echo"
INCLUDE_RULE = "include-tainted"
EVAL_RULE = "eval-tainted"
BACKTICK_RULE = "cmd-backtick"
VARFUNC_RULE = "variable-function-tainted"
HEADER_REDIRECT_RULE = "redirect-header"

# Functions that never return request data and never pass taint (fast path).
OPAQUE = frozenset({"count", "time", "microtime", "rand", "mt_rand", "uniqid", "function_exists", "defined",
                    "class_exists", "method_exists", "is_array", "is_object", "is_null", "is_bool",
                    "get_option", "get_current_user_id", "wp_get_current_user", "current_time"})

_LOCATION_RX = re.compile(r"^\s*location\s*:", re.I)


def is_location_literal(s):
    return bool(_LOCATION_RX.match(s or ""))
