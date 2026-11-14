"""Rule catalogue for ``phpwarden code`` (first-party PHP code scanning).

Design goal: few rules, almost no false positives.  Taint rules only fire
when user input (superglobals, framework request accessors) demonstrably
reaches a dangerous sink within one function/file scope without passing a
sanitizer that is appropriate for that sink.  Pattern rules only fire on
constructs that are dangerous regardless of data flow.

Each rule: id, category, severity, cwe, title, description, fix.
Taint sink specs live in ``TAINT_SINKS`` and are interpreted by code.py.
"""

SEVERITIES = ("critical", "high", "medium", "low")

RULES = []


def _r(rid, cat, sev, cwe, title, desc, fix, default=True, engine="any"):
    """default=False: an opt-in rule, run only when selected by id or with all_rules.
    engine="ast": the rule needs the whole-program engine (engine="ast"/"auto")."""
    RULES.append({"id": rid, "category": cat, "severity": sev, "cwe": cwe,
                  "title": title, "description": desc, "fix": fix, "default": default, "engine": engine})


# --- code execution ---------------------------------------------------------
C = "code-execution"
_r("eval-tainted", C, "critical", "CWE-95", "User input reaches eval()",
   "Request data is evaluated as PHP code, giving an attacker remote code execution.",
   "Never eval() request data. Replace with a whitelist/dispatch table.")
_r("eval-encoded-payload", C, "high", "CWE-506", "eval() of decoded payload",
   "eval(base64_decode(...))/gzinflate is the signature of obfuscated backdoors and webshells.",
   "Remove the code and investigate how it got there (possible compromise).")
_r("assert-tainted", C, "critical", "CWE-95", "User input reaches assert()",
   "assert() with a string argument evaluates it as code on PHP < 8.",
   "Never pass request data to assert(); use explicit validation.")
_r("create-function", C, "medium", "CWE-95", "create_function() used",
   "create_function() is an eval() wrapper, removed in PHP 8.",
   "Replace with an anonymous function (closure).")
_r("preg-replace-e", C, "high", "CWE-95", "preg_replace() with /e modifier",
   "The /e modifier evaluates the replacement as PHP code.",
   "Use preg_replace_callback().")
_r("call-user-func-tainted", C, "high", "CWE-470", "User-controlled callback name",
   "call_user_func*/array_map etc. invoked with a callable chosen by the request.",
   "Map allowed actions to callables via a fixed whitelist.")
_r("variable-function-tainted", C, "high", "CWE-470", "User-controlled variable function call",
   "$fn() is called where $fn comes from the request.",
   "Map allowed actions to callables via a fixed whitelist.")

# --- file inclusion ---------------------------------------------------------
C = "file-inclusion"
_r("include-tainted", C, "critical", "CWE-98", "User input in include/require path",
   "A request value controls the path of include/require (LFI/RFI, often RCE).",
   "Include from a fixed whitelist of files; never build include paths from input.")
_r("allow-url-include", C, "high", "CWE-98", "allow_url_include enabled at runtime",
   "Enabling allow_url_include makes any inclusion bug a remote code execution.",
   "Remove the ini_set() call; keep allow_url_include Off.")

# --- deserialization --------------------------------------------------------
C = "deserialization"
_r("unserialize-tainted", C, "critical", "CWE-502", "User input reaches unserialize()",
   "Deserializing request data allows PHP object injection (POP gadget chains -> RCE).",
   "Use json_decode(), or unserialize($x, ['allowed_classes' => false]) for trusted formats only.")
_r("unserialize-no-allowed-classes", C, "low", "CWE-502", "unserialize() without allowed_classes",
   "unserialize() of non-literal data without an allowed_classes restriction can instantiate arbitrary classes.",
   "Pass ['allowed_classes' => false] (or an explicit class list), or switch to JSON.", default=False)

# --- command injection ------------------------------------------------------
C = "command-injection"
for _fn in ("system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"):
    _r("cmd-" + _fn.replace("_", "-"), C, "critical", "CWE-78",
       "User input reaches %s()" % _fn,
       "Request data is passed to %s(), allowing OS command injection." % _fn,
       "Avoid the shell; if unavoidable, escape each argument with escapeshellarg() and whitelist values.")
_r("cmd-backtick", C, "critical", "CWE-78", "User input in backtick shell command",
   "A request value is interpolated into a `backtick` shell command.",
   "Use escapeshellarg() on every interpolated value, or avoid the shell.")
_r("mail-params-injection", C, "high", "CWE-88", "User input in mail() additional parameters",
   "The 5th mail() argument is passed to sendmail; attacker control allows writing files (RCE).",
   "Never pass request data as mail() additional_params; use escapeshellarg() and a fixed value.")

# --- SQL injection ----------------------------------------------------------
C = "sql-injection"
_r("sql-mysqli-query", C, "high", "CWE-89", "SQL injection via mysqli_query()",
   "A request value is concatenated/interpolated into a mysqli_query() string.",
   "Use mysqli prepared statements with bound parameters.")
_r("sql-mysql-query", C, "high", "CWE-89", "SQL injection via mysql_query()",
   "A request value reaches the removed mysql_* API.",
   "Migrate to PDO/mysqli prepared statements.")
_r("sql-pg-query", C, "high", "CWE-89", "SQL injection via pg_query()",
   "A request value is concatenated into a pg_query() string.",
   "Use pg_query_params() / pg_prepare().")
_r("sql-db-query", C, "high", "CWE-89", "SQL injection via ->query()/->exec()",
   "A request value is concatenated into a SQL string run by PDO/mysqli query()/exec().",
   "Use ->prepare() with placeholders and bind values.")
_r("sql-prepare-tainted", C, "high", "CWE-89", "Request data concatenated into prepare()",
   "Building the prepare() template from request data defeats the prepared statement.",
   "Put placeholders (? / :name / %s) in the template and pass values separately.")
_r("sql-wpdb", C, "high", "CWE-89", "SQL injection via $wpdb without prepare()",
   "A request value is interpolated into a $wpdb query without $wpdb->prepare().",
   "Wrap the query in $wpdb->prepare() with %s/%d placeholders.")
_r("sql-laravel-raw", C, "high", "CWE-89", "SQL injection via Laravel raw expression",
   "Request data is concatenated into DB::raw()/whereRaw()/selectRaw()/orderByRaw().",
   "Use bindings: whereRaw('col = ?', [$value]); whitelist identifiers for ORDER BY.")
_r("sql-laravel-db", C, "high", "CWE-89", "SQL injection via DB::select/statement/unprepared",
   "Request data is concatenated into a raw DB facade query.",
   "Pass values as the bindings array: DB::select('... where id = ?', [$id]).")
_r("sql-doctrine", C, "high", "CWE-89", "SQL/DQL injection via Doctrine",
   "Request data is concatenated into createQuery()/executeQuery()/createNativeQuery().",
   "Use setParameter() / parameter arrays instead of concatenation.")
_r("sql-sqlite", C, "high", "CWE-89", "SQL injection via SQLite API",
   "Request data is concatenated into an SQLite query.",
   "Use SQLite3::prepare() with bindValue().")

# --- path traversal / file operations ---------------------------------------
C = "path-traversal"
_r("path-read", C, "high", "CWE-22", "User-controlled path in file read",
   "A request value controls the path given to file_get_contents()/file()/fopen().",
   "Resolve with basename()/realpath() and verify the result is inside an allowed directory.")
_r("path-readfile", C, "high", "CWE-22", "User-controlled path in readfile()/show_source()",
   "A request value controls a file that is streamed to the client (arbitrary file disclosure).",
   "Map download IDs to paths server-side; never accept paths from the client.")
_r("path-write", C, "high", "CWE-73", "User-controlled path in file write",
   "A request value controls the path of file_put_contents()/fwrite target (can write webshells).",
   "Fix the directory and sanitize the file name with basename() plus an extension whitelist.")
_r("path-delete", C, "high", "CWE-22", "User-controlled path in unlink()/rmdir()",
   "A request value controls which file is deleted.",
   "Map IDs to paths server-side and verify containment with realpath().")
_r("path-move-upload", C, "high", "CWE-434", "Upload destination built from request data",
   "move_uploaded_file() destination uses a client-supplied name (traversal, .php upload).",
   "Generate the stored file name server-side and whitelist extensions.")
_r("upload-unrestricted", C, "high", "CWE-434", "Uploaded file stored without a type check",
   "move_uploaded_file() keeps the client's file name or extension and nothing in the function restricts the "
   "file type, so a .php file can be uploaded and run. basename() only stops directory traversal.",
   "Allow-list extensions (pathinfo + in_array) and check the content type (finfo/getimagesize); "
   "store under a server-generated name outside the web root.")
_r("path-copy-rename", C, "high", "CWE-22", "User-controlled path in copy()/rename()/symlink()",
   "A request value controls a filesystem copy/rename/link target.",
   "Never accept filesystem paths from the client.")

# --- SSRF ---------------------------------------------------------------------
C = "ssrf"
_r("ssrf-curl", C, "high", "CWE-918", "User-controlled URL in cURL request",
   "A request value is used as CURLOPT_URL / curl_init() URL (server-side request forgery).",
   "Validate the host against an allowlist and block internal address ranges.")
_r("ssrf-file-get-contents", C, "high", "CWE-918", "User-controlled URL in file_get_contents()/fopen()",
   "A request value completes an http(s) URL fetched by the server.",
   "Validate the host against an allowlist; prefer a fixed base URL plus encoded parameters.")
_r("ssrf-wp-remote", C, "high", "CWE-918", "User-controlled URL in wp_remote_*()",
   "A request value is fetched with wp_remote_get/post/request (not the wp_safe_* variants).",
   "Use wp_safe_remote_get()/wp_safe_remote_post() and validate the host.")
_r("ssrf-laravel-http", C, "high", "CWE-918", "User-controlled URL in Http:: client",
   "A request value is used as the URL of a Laravel Http:: request.",
   "Validate the host against an allowlist.")
_r("ssrf-fsockopen", C, "high", "CWE-918", "User-controlled host in fsockopen()",
   "A request value chooses the host the server connects to.",
   "Validate the host against an allowlist.")

# --- XSS ------------------------------------------------------------------------
C = "xss"
_r("xss-echo", C, "medium", "CWE-79", "Unescaped user input echoed",
   "Request data is written to the response with echo/print/die without escaping.",
   "Escape on output: htmlspecialchars($x, ENT_QUOTES, 'UTF-8') / esc_html() / e().")
_r("xss-printf", C, "medium", "CWE-79", "Unescaped user input in printf()",
   "Request data is formatted into the response by printf()/vprintf() without escaping.",
   "Escape each argument with htmlspecialchars()/esc_html().")

# --- open redirect ---------------------------------------------------------------
C = "open-redirect"
_r("redirect-header", C, "medium", "CWE-601", "Open redirect via header('Location: ...')",
   "The redirect target comes from the request.",
   "Redirect only to relative paths or an allowlist of hosts.")
_r("redirect-wp", C, "medium", "CWE-601", "Open redirect via wp_redirect()",
   "wp_redirect() with a request-supplied URL allows redirects to any host.",
   "Use wp_safe_redirect() (optionally with wp_validate_redirect()).")
_r("redirect-laravel", C, "medium", "CWE-601", "Open redirect via redirect()/Redirect::to()",
   "A Laravel redirect target comes from the request.",
   "Redirect to named routes, or validate the URL host against an allowlist.")

# --- other injection ----------------------------------------------------------------
C = "injection"
_r("ldap-injection", C, "high", "CWE-90", "LDAP filter built from request data",
   "A request value is concatenated into an LDAP search filter.",
   "Escape with ldap_escape($v, '', LDAP_ESCAPE_FILTER).")
_r("xpath-injection", C, "medium", "CWE-643", "XPath expression built from request data",
   "A request value is concatenated into an XPath query.",
   "Whitelist or strictly validate the value before using it in XPath.")
_r("session-fixation", C, "medium", "CWE-384", "Session ID set from request data",
   "session_id() is set from client input (session fixation).",
   "Let PHP generate IDs; call session_regenerate_id(true) on login.")
_r("ini-set-tainted", C, "high", "CWE-15", "PHP configuration set from request data",
   "ini_set()/putenv() with request data lets an attacker change runtime configuration.",
   "Never pass request data to ini_set()/putenv().")
_r("variable-variable-tainted", C, "high", "CWE-621", "Variable variable named by request data",
   "$$name where $name comes from the request lets attackers overwrite arbitrary variables.",
   "Use an array with whitelisted keys instead of variable variables.")
_r("extract-superglobal", C, "high", "CWE-621", "extract() on request superglobal",
   "extract($_GET/$_POST/$_REQUEST) re-creates register_globals: attackers can overwrite any variable.",
   "Read the specific keys you need from the request.")
_r("parse-str-one-arg", C, "medium", "CWE-621", "parse_str() without result array",
   "parse_str() with one argument writes variables into the current scope (removed in PHP 8).",
   "Pass a second argument: parse_str($qs, $out).")

# --- crypto / TLS ---------------------------------------------------------------------
C = "crypto"
_r("weak-hash-password", C, "high", "CWE-916", "Password hashed with md5()/sha1()",
   "Fast unsalted hashes are cracked trivially; passwords need a slow adaptive hash.",
   "Use password_hash() / password_verify().")
_r("crypt-no-salt", C, "low", "CWE-759", "crypt() without salt",
   "crypt() with one argument uses a weak, implementation-defined salt.",
   "Use password_hash().")
_r("weak-random-secret", C, "medium", "CWE-338", "Predictable random used for a secret",
   "rand()/mt_rand()/uniqid()/lcg_value()/str_shuffle() are not cryptographically secure but generate a token/password/nonce.",
   "Use random_bytes() / random_int() / bin2hex(random_bytes(32)).")
_r("openssl-ecb", C, "medium", "CWE-327", "openssl_encrypt() with ECB mode",
   "ECB mode leaks plaintext structure and has no integrity.",
   "Use an AEAD mode such as aes-256-gcm with a random IV, or libsodium.")
_r("mcrypt-deprecated", C, "low", "CWE-327", "mcrypt_* used",
   "mcrypt is abandoned and removed in PHP 7.2.",
   "Use openssl_* with AEAD modes or libsodium (sodium_crypto_*).")
_r("tls-verify-disabled", C, "high", "CWE-295", "TLS certificate verification disabled",
   "CURLOPT_SSL_VERIFYPEER/VERIFYHOST, 'verify_peer', 'sslverify' or Guzzle 'verify' turned off: man-in-the-middle possible.",
   "Keep verification on; point CURLOPT_CAINFO / 'verify' at a CA bundle if needed.")

# --- insecure configuration --------------------------------------------------------------
C = "config"
_r("display-errors-on", C, "low", "CWE-209", "display_errors enabled at runtime",
   "Error messages with paths and SQL leak to visitors.",
   "Log errors (log_errors=On) and keep display_errors Off in production.")
_r("phpinfo-call", C, "low", "CWE-200", "phpinfo() call in application code",
   "phpinfo() discloses configuration, paths and environment secrets.",
   "Remove the call or protect it behind admin authentication.")
_r("session-cookie-insecure-ini", C, "low", "CWE-1004", "Session cookie flags disabled",
   "ini_set('session.cookie_httponly'/'session.cookie_secure', 0) weakens the session cookie.",
   "Keep session.cookie_httponly=1 and session.cookie_secure=1 (and cookie_samesite).")
_r("cookie-insecure", C, "low", "CWE-614", "Sensitive cookie without Secure/HttpOnly",
   "A session/auth-like cookie is set without both the secure and httponly flags.",
   "setcookie($n, $v, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']).")

# --- secrets ---------------------------------------------------------------------------------
C = "secrets"
_r("hardcoded-secret", C, "medium", "CWE-798", "Hardcoded credential",
   "A literal password/secret/API key/token is committed in source.",
   "Load it from the environment (getenv/env()) or a secret store and rotate the exposed value.")
_r("hardcoded-private-key", C, "high", "CWE-321", "Private key embedded in source",
   "A PEM private key literal is committed in source.",
   "Move the key to a protected file/secret store and rotate it.")
_r("hardcoded-aws-key", C, "high", "CWE-798", "AWS access key ID in source",
   "An AKIA/ASIA access key ID literal is committed in source.",
   "Revoke the key in IAM and load credentials from the environment/instance role.")

# --- WordPress -------------------------------------------------------------------------------
C = "wordpress"
_r("wp-nopriv-ajax-no-auth", C, "high", "CWE-862", "Unauthenticated AJAX handler performs writes",
   "A wp_ajax_nopriv_ handler changes options/users/posts/DB without a nonce or capability check.",
   "Add check_ajax_referer() and current_user_can(); drop the nopriv hook if not needed.")
_r("wp-ajax-no-nonce", C, "medium", "CWE-352", "AJAX handler performs writes without nonce check",
   "A wp_ajax_ handler writes without check_ajax_referer()/wp_verify_nonce() (CSRF).",
   "Call check_ajax_referer('action') and current_user_can() before writing.")
_r("wp-rest-open-write", C, "medium", "CWE-862", "REST route with __return_true permission writes data",
   "register_rest_route() with 'permission_callback' => '__return_true' whose callback writes.",
   "Use a permission_callback that checks current_user_can().")

# --- Laravel ---------------------------------------------------------------------------------
C = "laravel"
_r("laravel-app-debug-env", C, "high", "CWE-489", "APP_DEBUG=true in committed .env",
   "Debug mode exposes stack traces, environment variables and secrets (Ignition RCE history).",
   "Set APP_DEBUG=false in production and do not commit .env (add it to .gitignore).")
_r("laravel-guarded-empty", C, "low", "CWE-915", "Model with $guarded = []",
   "All attributes are mass assignable; request data passed to create()/update() can set any column.",
   "Declare $fillable with the allowed columns.")

# --- XXE ----------------------------------------------------------------------------------------
C = "xxe"
_r("xxe-entity-loader", C, "high", "CWE-611", "External entity loader enabled",
   "libxml_disable_entity_loader(false) re-enables external entity loading.",
   "Remove the call; do not enable entity substitution.")
_r("xxe-noent", C, "high", "CWE-611", "XML parsed with LIBXML_NOENT",
   "LIBXML_NOENT substitutes entities, enabling XXE file disclosure/SSRF.",
   "Remove LIBXML_NOENT (and LIBXML_DTDLOAD).")
_r("xxe-xmlreader-subst", C, "high", "CWE-611", "XMLReader entity substitution enabled",
   "XMLReader::SUBST_ENTITIES set to true enables XXE.",
   "Do not enable SUBST_ENTITIES.")

# --- found by the AST engine (whole-program taint + framework models) --------
C = "framework"
_r("mass-assignment", C, "high", "CWE-915", "Whole request mass-assigned to an Eloquent model",
   "The complete request ($request->all(), except(), input()) is passed to create()/fill()/update() on a model "
   "with $guarded = [] (or through forceFill/forceCreate), so a request can set any column, e.g. is_admin.",
   "Pass $request->validated() or $request->only([...]) with an explicit list, and declare $fillable.", engine="ast")
_r("blade-raw", "xss", "medium", "CWE-79", "Request data printed unescaped in a Blade template",
   "A value that comes from the request reaches {!! ... !!} in a Blade view, which prints it without escaping.",
   "Use {{ ... }} (escaped), or sanitize with clean()/strip_tags before using {!! !!}.", engine="ast")
_r("twig-raw", "xss", "medium", "CWE-79", "Request data printed with |raw in a Twig template",
   "A value that comes from the request is printed with the |raw filter or inside {% autoescape false %}.",
   "Remove |raw, or sanitize the value (e.g. with an HTML sanitizer) before rendering.", engine="ast")
_r("xss-response", "xss", "medium", "CWE-79", "Request data returned as an HTML response body",
   "Request data is the body of a Response with the default text/html content type.",
   "Escape the value, return JSON (JsonResponse/response()->json()), or set a non-HTML Content-Type.", engine="ast")
_r("ssrf-http-client", "ssrf", "high", "CWE-918", "User-controlled URL in an HTTP client request",
   "A request value is used as the URL of a Guzzle / Symfony HttpClient / PSR-18 request (server-side request forgery).",
   "Allow-list hosts and schemes before requesting a URL that comes from the request.", engine="ast")
_r("cmd-process", "command-injection", "critical", "CWE-78", "User input in a shell command line (Process)",
   "Request data is part of a command string given to Process::fromShellCommandline(), new Process(string) or "
   "Laravel's Process::run(), which runs it through a shell.",
   "Pass the command as an array of arguments (new Process(['cmd', $arg])) and validate each value.", engine="ast")
_r("mail-header-injection", "injection", "medium", "CWE-93", "User input in mail headers",
   "Request data is used in the headers argument of mail()/wp_mail(); a newline lets an attacker add headers.",
   "Never build mail headers from request data; strip CR/LF and validate addresses.", engine="ast")
_r("wp-option-key-tainted", "wordpress", "high", "CWE-15", "Request data chooses which option or meta key is written",
   "update_option()/update_user_meta() and similar are called with a key taken from the request, so a request can "
   "overwrite any setting (e.g. users_can_register, default_role, wp_capabilities).",
   "Map allowed keys from a fixed list; never use a request value as the option or meta name.", engine="ast")

RULES_BY_ID = {r["id"]: r for r in RULES}

# ---------------------------------------------------------------------------
# Taint sink specs.  args: list of positional indices (-1 = last, "*" = any).
# taint: the taint kind that must survive sanitizers for the rule to fire.
DB_RECEIVER = r"(?i)(db|pdo|conn|mysqli|sqlite|database|link|dbh)"
TAINT_SINKS = [
    # code execution
    {"rule": "eval-tainted", "fn": ["eval"], "args": [0], "taint": "code"},
    {"rule": "assert-tainted", "fn": ["assert"], "args": [0], "taint": "code"},
    {"rule": "call-user-func-tainted",
     "fn": ["call_user_func", "call_user_func_array", "forward_static_call",
            "forward_static_call_array", "array_map", "usort", "array_filter"],
     "args": {"array_filter": [1]}, "default_args": [0], "taint": "code"},
    # deserialization
    {"rule": "unserialize-tainted", "fn": ["unserialize", "maybe_unserialize"], "args": [0], "taint": "deser"},
    # commands
    {"rule": "cmd-system", "fn": ["system"], "args": [0], "taint": "cmd"},
    {"rule": "cmd-exec", "fn": ["exec"], "args": [0], "taint": "cmd"},
    {"rule": "cmd-shell-exec", "fn": ["shell_exec"], "args": [0], "taint": "cmd"},
    {"rule": "cmd-passthru", "fn": ["passthru"], "args": [0], "taint": "cmd"},
    {"rule": "cmd-popen", "fn": ["popen"], "args": [0], "taint": "cmd"},
    {"rule": "cmd-proc-open", "fn": ["proc_open"], "args": [0], "taint": "cmd"},
    {"rule": "cmd-pcntl-exec", "fn": ["pcntl_exec"], "args": [0, 1], "taint": "cmd"},
    {"rule": "mail-params-injection", "fn": ["mail"], "args": [4], "taint": "cmd"},
    # SQL
    {"rule": "sql-mysqli-query", "fn": ["mysqli_query", "mysqli_real_query", "mysqli_multi_query"], "args": [1], "taint": "sql"},
    {"rule": "sql-mysql-query", "fn": ["mysql_query", "mysql_db_query", "mysql_unbuffered_query"], "args": [0], "taint": "sql"},
    {"rule": "sql-pg-query", "fn": ["pg_query", "pg_send_query"], "args": [-1], "taint": "sql"},
    {"rule": "sql-sqlite", "fn": ["sqlite_query", "sqlite_exec"], "args": [0, 1], "taint": "sql"},
    {"rule": "sql-prepare-tainted", "fn": ["mysqli_prepare"], "args": [1], "taint": "sql"},
    {"rule": "sql-wpdb", "method": ["query", "get_results", "get_var", "get_row", "get_col"],
     "receiver": r"(?i)^wpdb$", "args": [0], "taint": "sql"},
    {"rule": "sql-prepare-tainted", "method": ["prepare"], "receiver": r"(?i)(db|pdo|conn|mysqli|sqlite|database|link|dbh)",
     "args": [0], "taint": "sql"},
    {"rule": "sql-sqlite", "method": ["querysingle"], "args": [0], "taint": "sql"},
    {"rule": "sql-db-query", "method": ["query", "exec", "multi_query", "real_query", "unbuffered_query"],
     "receiver": DB_RECEIVER, "args": [0], "taint": "sql"},
    {"rule": "sql-laravel-raw", "method": ["whereraw", "orwhereraw", "selectraw", "orderbyraw", "havingraw",
                                           "orhavingraw", "groupbyraw", "fromraw"], "args": [0], "taint": "sql"},
    {"rule": "sql-laravel-raw", "static": ["db"], "names": ["raw"], "args": [0], "taint": "sql"},
    {"rule": "sql-laravel-db", "static": ["db"], "names": ["select", "selectone", "statement", "unprepared",
                                                           "insert", "update", "delete", "affectingstatement"],
     "args": [0], "taint": "sql"},
    {"rule": "sql-doctrine", "method": ["createquery", "createnativequery", "executequery", "executestatement",
                                        "executeupdate", "fetchallassociative", "fetchassociative", "fetchone"],
     "args": [0], "taint": "sql"},
    # path
    {"rule": "path-read", "fn": ["file_get_contents", "file", "fopen", "parse_ini_file", "simplexml_load_file"],
     "args": [0], "taint": "path", "ssrf_rule": "ssrf-file-get-contents"},
    {"rule": "path-readfile", "fn": ["readfile", "highlight_file", "show_source", "fpassthru"], "args": [0], "taint": "path"},
    {"rule": "path-write", "fn": ["file_put_contents"], "args": [0], "taint": "path"},
    {"rule": "path-delete", "fn": ["unlink", "rmdir"], "args": [0], "taint": "path"},
    {"rule": "path-move-upload", "fn": ["move_uploaded_file"], "args": [1], "taint": "path"},
    {"rule": "path-copy-rename", "fn": ["copy", "rename", "symlink", "link"], "args": [0, 1], "taint": "path"},
    # SSRF
    {"rule": "ssrf-curl", "fn": ["curl_init"], "args": [0], "taint": "url"},
    {"rule": "ssrf-wp-remote", "fn": ["wp_remote_get", "wp_remote_post", "wp_remote_head", "wp_remote_request",
                                      "download_url"], "args": [0], "taint": "url"},
    {"rule": "ssrf-laravel-http", "static": ["http"], "names": ["get", "post", "put", "patch", "delete", "head", "send"],
     "args": [0], "taint": "url"},
    {"rule": "ssrf-fsockopen", "fn": ["fsockopen", "pfsockopen", "stream_socket_client"], "args": [0], "taint": "url"},
    # XSS
    {"rule": "xss-echo", "fn": ["die", "exit"], "args": [0], "taint": "xss"},
    {"rule": "xss-printf", "fn": ["printf", "vprintf"], "args": "*", "taint": "xss"},
    # redirect
    {"rule": "redirect-wp", "fn": ["wp_redirect"], "args": [0], "taint": "redirect"},
    {"rule": "redirect-laravel", "fn": ["redirect"], "args": [0], "taint": "redirect"},
    {"rule": "redirect-laravel", "static": ["redirect"], "names": ["to", "away"], "args": [0], "taint": "redirect"},
    # other injection
    {"rule": "ldap-injection", "fn": ["ldap_search", "ldap_list", "ldap_read"], "args": [2], "taint": "ldap"},
    {"rule": "xpath-injection", "method": ["query", "evaluate"], "receiver": r"(?i)xpath", "args": [0], "taint": "xpath"},
    {"rule": "xpath-injection", "method": ["xpath"], "args": [0], "taint": "xpath"},
    {"rule": "session-fixation", "fn": ["session_id"], "args": [0], "taint": "session"},
    {"rule": "ini-set-tainted", "fn": ["ini_set", "putenv", "ini_alter"], "args": [0, 1], "taint": "env"},
]

# PHPGGC-inspired list of packages that ship a known POP gadget chain.
# Prefix entries end with "/".
GADGET_PACKAGES = [
    "monolog/monolog", "guzzlehttp/guzzle", "laravel/framework", "illuminate/",
    "symfony/process", "symfony/cache", "symfony/symfony", "symfony/http-kernel",
    "doctrine/", "phpunit/phpunit", "swiftmailer/swiftmailer", "yiisoft/yii2",
    "slim/slim", "zendframework/", "laminas/laminas-diactoros", "codeigniter4/framework",
    "cakephp/cakephp", "thinkphp/", "topthink/framework", "drupal/core",
    "phpseclib/phpseclib", "pear/archive_tar", "wordpress/",
]


# --- layer 5 (whole-program engine) -------------------------------------------
C = "second-order"
_r("second-order-injection", C, "high", "CWE-74", "Stored request data used later in a sink (second-order)",
   "Request data is saved under a fixed option or meta key and read back elsewhere, where it reaches a SQL query, "
   "HTML output, an include or another sink without being sanitised for that use.",
   "Sanitise when the value is used, not only when it is stored: prepare SQL, escape output, whitelist paths.",
   engine="ast")
C = "authorization"
_r("laravel-route-no-auth", C, "medium", "CWE-862", "State-changing route with no authentication or authorization",
   "A POST/PUT/PATCH/DELETE route reaches a database write, but neither the route (or its group) has auth "
   "middleware nor does the controller call authorize() or a Gate.",
   "Add ->middleware('auth') (or 'can:...') to the route or group, or call $this->authorize() in the controller.",
   engine="ast")
_r("symfony-route-no-auth", C, "medium", "CWE-862", "Controller action writes entities with no access check",
   "A #[Route] action persists or removes entities without #[IsGranted] or denyAccessUnlessGranted().",
   "Add #[IsGranted('ROLE_...')] or call $this->denyAccessUnlessGranted(); or cover the path in access_control.",
   engine="ast")
_r("laravel-idor-hint", C, "medium", "CWE-639", "Record from a route parameter changed without an ownership check",
   "An authenticated route loads a model from a route parameter and updates or deletes it, with no policy, Gate "
   "or ownership comparison, so one user may change another user's record (IDOR).",
   "Authorize with a policy ($this->authorize('update', $post)) or scope the query to the current user.",
   engine="ast")
C = "csrf"
_r("laravel-csrf-excluded", C, "medium", "CWE-352", "State-changing route excluded from CSRF protection",
   "A URI in VerifyCsrfToken::$except (or validateCsrfTokens(except: ...)) matches a POST/PUT/PATCH/DELETE web "
   "route, so another site can submit it on behalf of a signed-in user.",
   "Remove it from the exception list, or verify the caller another way (a webhook signature).",
   engine="ast")
_r("wp-admin-post-no-nonce", C, "medium", "CWE-352", "admin-post handler changes state without a nonce check",
   "An admin_post_ action handler writes options, posts or the database without check_admin_referer() or "
   "wp_verify_nonce(), so another site can trigger it for a logged-in administrator.",
   "Add a nonce to the form and call check_admin_referer('action') at the top of the handler.",
   engine="ast")


# rules appended after the table above (Stage C) must be indexed too
RULES_BY_ID.update({r["id"]: r for r in RULES})
