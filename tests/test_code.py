#!/usr/bin/env python3
"""Validate the first-party PHP code scanner (phpwarden code)."""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from phpwarden import code  # noqa: E402
from phpwarden.code_rules import RULES_BY_ID  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "code"
ok = True


def check(name, cond):
    global ok
    print(("PASS" if cond else "FAIL"), name)
    ok = ok and cond


def snippet(php, name="t.php", **kw):
    d = tempfile.mkdtemp()
    try:
        with open(os.path.join(d, name), "w") as fh:
            fh.write(php)
        return [f["rule"] for f in code.scan_project(d, **kw)["findings"]]
    finally:
        shutil.rmtree(d)


# --- vulnerable fixtures ------------------------------------------------------
vuln = code.scan_project(str(FIX / "vuln"), all_rules=True)
by = {}
for f in vuln["findings"]:
    by.setdefault((f["file"], f["rule"]), []).append(f["line"])
rules_hit = {f["rule"] for f in vuln["findings"]}

EXPECT = {
    "plain.php": ["sql-mysqli-query", "sql-db-query", "eval-tainted", "eval-encoded-payload", "cmd-system",
                  "cmd-backtick", "include-tainted", "unserialize-tainted", "xss-echo", "redirect-header",
                  "path-readfile", "path-write", "path-delete", "path-move-upload", "ssrf-curl",
                  "ssrf-file-get-contents", "variable-function-tainted", "call-user-func-tainted",
                  "extract-superglobal", "parse-str-one-arg", "weak-hash-password", "weak-random-secret",
                  "openssl-ecb", "display-errors-on", "tls-verify-disabled", "hardcoded-secret", "xxe-noent",
                  "xxe-entity-loader", "cookie-insecure", "variable-variable-tainted", "create-function",
                  "preg-replace-e", "unserialize-no-allowed-classes", "cmd-shell-exec"],
    "wp-plugin.php": ["wp-nopriv-ajax-no-auth", "wp-ajax-no-nonce", "sql-wpdb", "redirect-wp",
                      "wp-rest-open-write", "ssrf-wp-remote", "tls-verify-disabled"],
    "UserController.php": ["sql-laravel-raw", "sql-laravel-db", "redirect-laravel", "sql-doctrine",
                           "hardcoded-secret"],
    "app/Models/Post.php": ["laravel-guarded-empty"],
    ".env": ["laravel-app-debug-env"],
}
for fname, rids in EXPECT.items():
    for rid in rids:
        check("vuln %s fires %s" % (fname, rid), (fname, rid) in by)

check("taint through variable ($id -> $q -> mysqli_query)", by.get(("plain.php", "sql-mysqli-query")) == [5])
check("taint through interpolation (\"...$ua...\" HTTP_USER_AGENT)", 45 in by.get(("plain.php", "sql-db-query"), []))
check("php://input is a source", 47 in by.get(("plain.php", "unserialize-tainted"), []))
check("request('id') helper taints whereRaw", 24 in by.get(("UserController.php", "sql-laravel-raw"), []))
check("Symfony $request->query->get() taints Doctrine", ("UserController.php", "sql-doctrine") in by)
check("$_FILES tmp_name is not a source but ['name'] is", by.get(("plain.php", "path-move-upload")) == [20])
check("eval-tainted is critical", RULES_BY_ID["eval-tainted"]["severity"] == "critical")
check("no duplicate (rule,file,line)", len({(f["rule"], f["file"], f["line"]) for f in vuln["findings"]})
      == len(vuln["findings"]))
check("findings sorted by severity", [code.SEV_RANK[f["severity"]] for f in vuln["findings"]]
      == sorted(code.SEV_RANK[f["severity"]] for f in vuln["findings"]))
f0 = vuln["findings"][0]
check("finding has all fields", all(k in f0 for k in ("rule", "title", "severity", "cwe", "file", "line", "column",
                                                     "snippet", "message", "fix", "context")))
check("snippet trimmed <=200", all(len(f["snippet"]) <= 200 for f in vuln["findings"]))

# --- suppression / scope -------------------------------------------------------
check("suppression on previous line", ("suppressed.php", "cmd-system") not in by)
check("suppression on same line", ("suppressed.php", "cmd-passthru") not in by)
check("vendor/ skipped", not any(f["file"].startswith("vendor/") for f in vuln["findings"]))
check("tests/ skipped by default", not any(f["file"].startswith("tests/") for f in vuln["findings"]))
with_tests = code.scan_project(str(FIX / "vuln"), include_tests=True)
check("include_tests=True scans tests/", any(f["file"].startswith("tests/") for f in with_tests["findings"]))
check("vendor/ skipped even with include_tests", not any(f["file"].startswith("vendor/") for f in with_tests["findings"]))
only = code.scan_project(str(FIX / "vuln"), rules=["eval-tainted"])
check("rules= filter", {f["rule"] for f in only["findings"]} == {"eval-tainted"})

# --- precision: safe fixtures ------------------------------------------------------
safe = code.scan_project(str(FIX / "safe"))
check("safe fixtures scanned (3 files)", safe["files_scanned"] == 3)
check("ZERO findings in safe fixtures", safe["findings"] == [])
for f in safe["findings"]:
    print("   unexpected:", f["rule"], f["file"], f["line"], f["snippet"])
check("exit_code 0 for safe", code.exit_code(safe) == 0)
check("exit_code 1 for vuln", code.exit_code(vuln) == 1)

# --- targeted snippets ---------------------------------------------------------------
check("comment mentioning eval( is ignored", snippet("<?php\n// eval($_GET['x']);\n") == [])
check("string mentioning system( is ignored", snippet("<?php\n$a = 'system($_GET[1])';\n") == [])
check("heredoc interpolates $_GET into echo -> xss", "xss-echo" in snippet("<?php\necho <<<H\nHi {$_GET['n']}\nH;\n"))
check("nowdoc does not interpolate", snippet("<?php\necho <<<'H'\nHi {$_GET['n']}\nH;\n") == [])
check("html outside <?php ignored", snippet("<p>eval($_GET['x'])</p><?php echo 'x'; ?>") == [])
check("<?= tainted short echo", "xss-echo" in snippet("<p><?= $_GET['q'] ?></p>", "v.phtml"))
check("esc_html clears xss", snippet("<?php echo esc_html($_GET['q']);") == [])
check("esc_html does NOT clear sql", "sql-wpdb" in snippet("<?php $v=esc_html($_GET['q']); $wpdb->query(\"x $v\");"))
check("escapeshellarg clears cmd", snippet("<?php exec('ls ' . escapeshellarg($_GET['d']));") == [])
check("taint cleared by reassignment", snippet("<?php $a=$_GET['a']; $a='x'; system($a);") == [])
check("taint scoped to function", snippet("<?php $a=$_GET['a'];\nfunction f($a){ system($a); }") == [])
check("closure inherits parent scope", "cmd-system" in snippet("<?php $a=$_GET['a']; $f=function() use ($a) { system($a); };"))
check(".= propagates", "cmd-exec" in snippet("<?php $c='ls '; $c .= $_POST['d']; exec($c);"))
check("foreach propagates", "eval-tainted" in snippet("<?php foreach ($_POST as $k => $v) { eval($v); }"))
check("unknown function drops taint", snippet("<?php $a = my_clean($_GET['a']); system($a);") == [])
check("comparison yields bool", snippet("<?php $a = $_GET['a'] == 'x'; system($a);") == [])
check("(int) cast clears", snippet("<?php system('kill ' . (int) $_GET['pid']);") == [])
check("ternary with source still tainted", "cmd-system" in snippet("<?php $a = isset($_GET['a']) ? $_GET['a'] : ''; system($a);"))
check("$wpdb->prepare is not sql-wpdb", snippet("<?php $wpdb->query($wpdb->prepare('x %s', $_GET['a']));") == [])
check("prepare with interpolated input fires", "sql-prepare-tainted" in snippet("<?php $pdo->prepare(\"SELECT * FROM t WHERE a = '{$_GET['a']}'\");"))
check("unserialize allowed_classes ok", snippet("<?php $o = unserialize($x, ['allowed_classes' => false]);") == [])
check("md5 of filename ok", snippet("<?php $e = md5($filename);") == [])
check("$_SERVER['DOCUMENT_ROOT'] is not a source", snippet("<?php include $_SERVER['DOCUMENT_ROOT'] . '/x.php';") == [])
check("$_SERVER['PHP_SELF'] echoed fires", "xss-echo" in snippet("<?php echo $_SERVER['PHP_SELF'];"))
check("placeholder secret skipped", snippet("<?php $password = 'your-password-here'; define('API_KEY', 'changeme123');") == [])
check("define secret fires", "hardcoded-secret" in snippet("<?php define('STRIPE_SECRET_KEY', 'fixture-not-a-real-key-51Hx');"))
check("env() default not a secret", snippet("<?php return ['key' => env('APP_KEY'), 'password' => env('DB_PASSWORD', '')];") == [])
check("AWS key literal", "hardcoded-aws-key" in snippet("<?php $c = ['k' => 'AKIAIOSFODNN7EXAMPLE'];"))
check("PEM private key literal", "hardcoded-private-key" in snippet("<?php $k = \"-----BEGIN RSA PRIVATE KEY-----\\nMIIE\";"))
check("random_bytes token ok", snippet("<?php $token = bin2hex(random_bytes(16));") == [])
check("mt_rand for nonce fires", "weak-random-secret" in snippet("<?php $nonce = mt_rand(1000, 9999);"))
check("rand for non-secret ok", snippet("<?php $color = rand(0, 255);") == [])
check("Guzzle verify=>false", "tls-verify-disabled" in snippet("<?php $c->get($u, ['verify' => false]);"))
check("mcrypt flagged", "mcrypt-deprecated" in snippet("<?php mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $k, $d, MCRYPT_MODE_CBC);"))
check("XMLReader SUBST_ENTITIES", "xxe-xmlreader-subst" in snippet("<?php $r->setParserProperty(XMLReader::SUBST_ENTITIES, true);"))
check("phpinfo flagged", "phpinfo-call" in snippet("<?php phpinfo();"))
check("allow_url_include", "allow-url-include" in snippet("<?php ini_set('allow_url_include', '1');"))
check("ldap injection", "ldap-injection" in snippet("<?php ldap_search($c, $dn, '(uid=' . $_GET['u'] . ')');"))
check("ldap_escape clears", snippet("<?php ldap_search($c, $dn, '(uid=' . ldap_escape($_GET['u'], '', LDAP_ESCAPE_FILTER) . ')');") == [])
check("mail 5th param", "mail-params-injection" in snippet("<?php mail($to, $s, $m, '', '-f' . $_POST['from']);"))
check("Laravel Http::get SSRF", "ssrf-laravel-http" in snippet("<?php Http::get($request->input('url'));"))
check("Request::input static source", "cmd-exec" in snippet("<?php exec(Request::input('c'));"))
check("filter_var VALIDATE_INT clears", snippet("<?php $p = filter_var($_GET['p'], FILTER_VALIDATE_INT); include \"p$p.php\";") == [])
check("method call result drops taint", snippet("<?php $u = $repo->find($_GET['id']); echo $u;") == [])
check("crypt without salt", "crypt-no-salt" in snippet("<?php $h = crypt($pw);"))
check("session_id from input", "session-fixation" in snippet("<?php session_id($_GET['sid']);"))
check("pg_query last arg", "sql-pg-query" in snippet("<?php pg_query($db, 'SELECT ' . $_GET['c']);"))
check("cookie with secure+httponly ok", snippet("<?php setcookie('auth', $v, time()+3600, '/', '', true, true);") == [])
check("non-session cookie ok", snippet("<?php setcookie('theme', 'dark');") == [])

# --- gadget-chain context boost --------------------------------------------------------
g = code.scan_project(str(FIX / "gadget"))
gf = [f for f in g["findings"] if f["rule"] == "unserialize-tainted"]
check("gadget fixture unserialize-tainted found", len(gf) == 1)
check("gadget context lists monolog", gf and gf[0]["context"] == ["gadget-chain: monolog/monolog"])
check("gadget severity capped at critical", gf and gf[0]["severity"] == "critical")
d = tempfile.mkdtemp()
try:
    with open(os.path.join(d, "a.php"), "w") as fh:
        fh.write("<?php $o = unserialize($cache);\n")
    check("unserialize-no-allowed-classes is opt-in: off by default", code.scan_project(d)["findings"] == [])
    check("... and listed with default false", [r["default"] for r in code.list_rules()
                                                if r["id"] == "unserialize-no-allowed-classes"] == [False]
          and sum(1 for r in code.list_rules() if not r["default"]) == 1)
    check("... and on when selected by id", [f["rule"] for f in code.scan_project(
        d, rules=["unserialize-no-allowed-classes"])["findings"]] == ["unserialize-no-allowed-classes"])
    plain = code.scan_project(d, all_rules=True)
    check("no lock: low, no context", plain["findings"][0]["severity"] == "low" and not plain["findings"][0]["context"])
    lf = [{"package": "guzzlehttp/guzzle", "cve": "CVE-2022-31090", "known_exploited": True}]
    boosted = code.scan_project(d, lock_findings=lf, all_rules=True)
    bf = boosted["findings"][0]
    check("lock_findings package boosts low->medium", bf["severity"] == "medium")
    check("lock_findings context has gadget + KEV",
          "gadget-chain: guzzlehttp/guzzle" in bf["context"] and any(c.startswith("known-exploited") for c in bf["context"]))
finally:
    shutil.rmtree(d)

# --- benchmark regressions (bench/code-2026-11) --------------------------------------------
# 1. statements inside switch/case, match, and the alternative (colon) syntax
check("switch/case body is analysed", "xss-echo" in snippet(
    '<?php switch ($s) { case "1": $f = $_REQUEST["u"]; echo "<meta url=" . $f . ">"; break; }'))
check("switch/default body is analysed", "cmd-system" in snippet(
    '<?php switch ($s) { case 1: break; default: $c = $_GET["c"]; system("ls " . $c); }'))
check("switch with sanitised value stays quiet", snippet(
    '<?php switch ($s) { case "1": $f = intval($_REQUEST["u"]); echo "<b>" . $f . "</b>"; break; }') == [])
check("case with a ternary in its expression still splits", "cmd-exec" in snippet(
    '<?php switch ($s) { case ($a ? 1 : 2): $c = $_GET["c"]; exec($c); }'))
check("if(): ... endif; body is analysed", "sql-mysqli-query" in snippet(
    '<?php if ($ok): $id = $_GET["id"]; mysqli_query($c, "SELECT * FROM t WHERE id=" . $id); endif;'))
check("else: branch is analysed", "xss-echo" in snippet('<?php if ($a): echo 1; else: echo $_GET["q"]; endif;'))
check("foreach(): ... endforeach; taints the loop variable", "xss-echo" in snippet(
    '<?php foreach ($_POST["items"] as $it): echo $it; endforeach;'))
check("while(): ... endwhile; body is analysed", "cmd-passthru" in snippet(
    '<?php while ($n--): passthru($_GET["cmd"]); endwhile;'))
check("brace-less if body is analysed", "xss-echo" in snippet('<?php if ($a) echo $_GET["q"];'))
check("match arm carrying request data taints the result", "include-tainted" in snippet(
    '<?php $p = match ($k) { "a" => $_GET["page"], default => "home" }; include $p;'))
check("match with only literals stays quiet", snippet(
    '<?php $p = match ($_GET["k"]) { "a" => "a.php", default => "home.php" }; include $p;') == [])

check("a later case that encodes does not clean the value for the other cases", "xss-echo" in snippet(
    '<?php $ua = $_SERVER["HTTP_USER_AGENT"]; switch ($lvl) { case "0": break; '
    'case "5": $ua = htmlspecialchars($ua); break; } echo $ua;'))

check("an elseif/else branch does not clean what a sibling branch assigned", "path-readfile" in snippet(
    '<?php if ($insecure) { $f = $_REQUEST["f"]; } elseif ($strict) { $f = $allowed[$i]; } else { $f = "a.php"; } highlight_file($f);'))
check("... while overwriting in a plain if after the fact still cleans (unchanged behaviour)", snippet(
    '<?php $f = $_REQUEST["f"]; if (!isset($allowed[$f])) { $f = "a.php"; } highlight_file($f);') == [])

# 2. assignments inside expressions
check("assignment in both ternary branches", "cmd-shell-exec" in snippet(
    '<?php $p ? $h = $_POST["h"] : $h = $_REQUEST["h"]; shell_exec("nslookup " . $h);'))
check("assignment inside an if condition", "cmd-system" in snippet(
    '<?php if (($x = $_GET["a"])) { system($x); }'))
check("assignment inside a while condition", "xss-echo" in snippet(
    '<?php while ($line = $_POST["l"]) { echo $line; break; }'))
check("chained assignment taints both names", "cmd-exec" in snippet('<?php $a = $b = $_GET["x"]; exec($b);')
      and "cmd-exec" in snippet('<?php $a = $b = $_GET["x"]; exec($a);'))
check("ternary assignment of sanitised values stays quiet", snippet(
    '<?php $p ? $h = intval($_POST["h"]) : $h = 0; shell_exec("nslookup " . $h);') == [])
check("default parameter values are not assignments of request data", snippet(
    '<?php function f($a = 1, $b = "x") { return $a; } system("ls");') == [])

# 3. SQL string escaping only protects inside quotes
ESC = '<?php $id = mysqli_real_escape_string($c, $_GET["id"]); '
check("escaped value used unquoted is still injectable (interpolation)", "sql-mysqli-query" in snippet(
    ESC + '$q = "SELECT * FROM users WHERE user_id = $id;"; mysqli_query($c, $q);'))
check("escaped value used unquoted (concatenation at the sink)", "sql-mysqli-query" in snippet(
    ESC + 'mysqli_query($c, "SELECT * FROM users WHERE user_id = " . $id);'))
check("escaped value inside single quotes is safe", snippet(
    ESC + '$q = "SELECT * FROM users WHERE user_id = \'$id\';"; mysqli_query($c, $q);') == [])
check("escaped value inside quotes via concatenation is safe", snippet(
    ESC + 'mysqli_query($c, "SELECT * FROM users WHERE name = \'" . $id . "\'");') == [])
check("addslashes unquoted fires, quoted does not",
      "sql-mysqli-query" in snippet('<?php $n = addslashes($_POST["n"]); mysqli_query($c, "SELECT * FROM t LIMIT " . $n);')
      and snippet('<?php $n = addslashes($_POST["n"]); mysqli_query($c, "SELECT * FROM t WHERE a=\\"$n\\"");') == [])
check("esc_sql unquoted fires in $wpdb->query", "sql-wpdb" in snippet(
    '<?php $o = esc_sql($_GET["o"]); $wpdb->query("SELECT * FROM t ORDER BY $o");'))
check("escaped then cast to int is safe unquoted", snippet(
    ESC + '$id = (int) $id; mysqli_query($c, "SELECT * FROM users WHERE user_id = $id");') == [])
check("escaped value passed to sprintf inside quotes is not judged", snippet(
    ESC + 'mysqli_query($c, sprintf("SELECT * FROM users WHERE name = \'%s\'", $id));') == [])

# 4. validation guards
check("is_numeric guard with exit clears the value", snippet(
    '<?php $id = $_GET["id"]; if (!is_numeric($id)) { die("bad"); } shell_exec("ping " . $id);') == [])
check("brace-less guard with return", snippet(
    '<?php function f() { $id = $_GET["id"]; if (!ctype_digit($id)) return; system("kill " . $id); }') == [])
check("positive guard wrapping the sink (all four octets)", snippet(
    '<?php $o = explode(".", $_REQUEST["ip"]); if ((is_numeric($o[0])) && (is_numeric($o[1])) && (sizeof($o) == 2)) '
    '{ $t = $o[0] . "." . $o[1]; shell_exec("ping " . $t); }') == [])
check("an unchecked element of the same array still fires", "cmd-shell-exec" in snippet(
    '<?php $o = explode(".", $_REQUEST["ip"]); if (is_numeric($o[0])) { shell_exec("ping " . $o[1]); }'))
check("guard does not leak out of its block", "cmd-shell-exec" in snippet(
    '<?php $id = $_GET["id"]; if (is_numeric($id)) { echo 1; } shell_exec("ping " . $id);'))
check("guard that does not exit is not a guard", "cmd-shell-exec" in snippet(
    '<?php $id = $_GET["id"]; if (!is_numeric($id)) { $err = 1; } shell_exec("ping " . $id);'))
check("in_array against a literal list (strict) with exit", snippet(
    '<?php $a = $_GET["a"]; if (!in_array($a, ["up", "down"], true)) { exit; } system("svc " . $a);') == [])
check("in_array without strict is not a guard (against numbers)", "cmd-system" in snippet(
    '<?php $a = $_GET["a"]; if (!in_array($a, [0, 1])) { exit; } system("svc " . $a);'))
check("anchored whitelist preg_match with exit", snippet(
    '<?php $t = $_GET["t"]; if (!preg_match(\'/^[a-z0-9_]+$/\', $t)) { die(); } include "tpl/" . $t . ".php";') == [])
check("unanchored preg_match is not a guard", "include-tainted" in snippet(
    '<?php $t = $_GET["t"]; if (!preg_match(\'/[a-z0-9_]+/\', $t)) { die(); } include "tpl/" . $t . ".php";'))
check("whitelist that allows dots or slashes is not a guard", "include-tainted" in snippet(
    '<?php $t = $_GET["t"]; if (!preg_match(\'/^[a-z0-9_.\\/]+$/\', $t)) { die(); } include "tpl/" . $t;'))
check("negated character class followed by wp_die (WordPress setup-config shape)", snippet(
    '<?php $prefix = $_POST["prefix"]; if (preg_match(\'|[^a-z0-9_]|i\', $prefix)) { wp_die("bad prefix"); } '
    'file_put_contents("cfg-" . $prefix . ".php", "x");') == [])
check("re-assignment after the guard is unchecked again", "cmd-system" in snippet(
    '<?php $id = $_GET["id"]; if (!is_numeric($id)) { die(); } $id = $_GET["other"]; system("x " . $id);'))
check("|| of negated guards with exit validates both", snippet(
    '<?php $a = $_GET["a"]; $b = $_GET["b"]; if (!is_numeric($a) || !is_numeric($b)) { return; } system("x $a $b");') == [])
check("&& of negated guards with exit validates neither", "cmd-system" in snippet(
    '<?php $a = $_GET["a"]; $b = $_GET["b"]; if (!is_numeric($a) && !is_numeric($b)) { return; } system("x $a $b");'))

check("preg_replace that strips everything outside a safe class cleans the value", snippet(
    '<?php $l = preg_replace(\'/[^a-zA-Z0-9_]/\', "", $_REQUEST["language"]); echo "<a href=?l=$l>x</a>"; include "lang/$l.php";') == [])
check("... a blacklist preg_replace does not", "xss-echo" in snippet(
    '<?php $l = preg_replace(\'/<script>/\', "", $_REQUEST["language"]); echo "<p>$l</p>";'))

# 5. global variables
check("global set inside a function is tainted at file scope", "include-tainted" in snippet(
    '<?php function pick() { global $page; $page = $_GET["page"]; } pick(); require_once($page);'))
check("... also when the function is defined after the use", "include-tainted" in snippet(
    '<?php pick(); require_once($page); function pick() { global $page; $page = $_GET["page"]; }'))
check("... and in another function that declares it global", "cmd-system" in snippet(
    '<?php function a() { global $c; $c = $_POST["c"]; } function b() { global $c; system($c); }'))
check("a local with the same name is not the global", snippet(
    '<?php function a() { $page = $_GET["page"]; } a(); require_once($page);') == [])
check("global set to a constant stays quiet", snippet(
    '<?php function pick() { global $page; $page = "home.php"; } pick(); require_once($page);') == [])

# 6. one level of same-file wrappers
W = '<?php function run_query($sql) { global $c; return mysqli_query($c, $sql); } '
check("wrapper function: tainted argument reported at the call site", "sql-mysqli-query" in snippet(
    W + 'run_query("SELECT * FROM t WHERE id=" . $_GET["id"]);'))
check("wrapper defined after the call", "sql-mysqli-query" in snippet(
    '<?php run_query("SELECT * FROM t WHERE id=" . $_GET["id"]); function run_query($sql) { return mysqli_query($GLOBALS["c"], $sql); }'))
check("wrapper called with a constant stays quiet", snippet(W + 'run_query("SELECT 1");') == [])
check("wrapper that sanitises its parameter is not a wrapper", snippet(
    '<?php function ping($h) { $h = escapeshellarg($h); return shell_exec("ping " . $h); } ping($_GET["h"]);') == [])
check("wrapper with a guarded parameter is not a wrapper", snippet(
    '<?php function ping($h) { if (!is_numeric($h)) { return; } return shell_exec("ping " . $h); } ping($_GET["h"]);') == [])
check("int-typed parameter is not a wrapper", snippet(
    '<?php function del(int $id) { return mysqli_query($GLOBALS["c"], "DELETE FROM t WHERE id=$id"); } del($_GET["id"]);') == [])
check("method wrapper via $this", "cmd-exec" in snippet(
    '<?php class R { function sh($cmd) { exec($cmd, $o); return $o; } function go() { return $this->sh("ls " . $_GET["d"]); } }'))
check("method wrapper via self::", "cmd-exec" in snippet(
    '<?php class R { static function sh($cmd) { exec($cmd); } static function go() { self::sh("ls " . $_GET["d"]); } }'))
check("call-site message names the wrapper", any("via run_query()" in f["message"] for f in (lambda d: (
    open(os.path.join(d, "t.php"), "w").write(W + 'run_query("SELECT * FROM t WHERE id=" . $_GET["id"]);'),
    code.scan_project(d)["findings"])[1])(tempfile.mkdtemp())))
check("function returning request data taints its result", "xss-echo" in snippet(
    '<?php function param($k) { return $_GET[$k]; } echo "<p>" . param("q") . "</p>";'))
check("... defined after the call, and through $this", "cmd-system" in snippet(
    '<?php class A { function go() { system("x " . $this->arg()); } function arg() { return $_POST["a"]; } }'))
check("function returning a cast value stays quiet", snippet(
    '<?php function param($k) { return (int) $_GET[$k]; } echo "<p>" . param("q") . "</p>";') == [])
check("a wrapper of a wrapper in the same file is followed", "cmd-system" in snippet(
    '<?php function a($x) { b($x); } function b($y) { system($y); } a($_GET["c"]);'))
check("parameter markers never fire on their own", snippet(
    '<?php function f($a, $b) { $$a = 1; echo $b; system($a); include $b; }') == [])

# 7. unrestricted upload
check("upload keeping the client name with only basename()", "upload-unrestricted" in snippet(
    '<?php $t = "uploads/" . basename($_FILES["up"]["name"]); move_uploaded_file($_FILES["up"]["tmp_name"], $t);'))
check("upload with an extension allow-list stays quiet", snippet(
    '<?php $n = basename($_FILES["up"]["name"]); $ext = strtolower(pathinfo($n, PATHINFO_EXTENSION)); '
    'if (!in_array($ext, ["jpg", "png"], true)) { die(); } move_uploaded_file($_FILES["up"]["tmp_name"], "uploads/" . $n);') == [])
check("upload checked with getimagesize stays quiet", snippet(
    '<?php $n = basename($_FILES["up"]["name"]); if (!getimagesize($_FILES["up"]["tmp_name"])) { die(); } '
    'move_uploaded_file($_FILES["up"]["tmp_name"], "uploads/" . $n);') == [])
check("upload stored under a server-generated name stays quiet", snippet(
    '<?php move_uploaded_file($_FILES["up"]["tmp_name"], "uploads/" . bin2hex(random_bytes(8)) . ".dat");') == [])
check("client-supplied MIME type is not validation (vulnerable)", "upload-unrestricted" in snippet(
    '<?php $t = "uploads/" . basename($_FILES["up"]["name"]); $ty = $_FILES["up"]["type"]; '
    'if ($ty == "image/jpeg" || $ty == "image/png") { move_uploaded_file($_FILES["up"]["tmp_name"], $t); }'))
check("client MIME type plus getimagesize on the temp file stays quiet", snippet(
    '<?php $t = "uploads/" . basename($_FILES["up"]["name"]); $ty = $_FILES["up"]["type"]; '
    'if ($ty == "image/png" && getimagesize($_FILES["up"]["tmp_name"])) { move_uploaded_file($_FILES["up"]["tmp_name"], $t); }') == [])
check("Laravel validation with mimes: counts as a check", "upload-unrestricted" not in snippet(
    '<?php function up($r) { $r->validate(["f" => "required|mimes:jpg,png"]); '
    'move_uploaded_file($_FILES["f"]["tmp_name"], "u/" . basename($_FILES["f"]["name"])); }'))
check("a check in another function does not count", "upload-unrestricted" in snippet(
    '<?php function ok($f) { return getimagesize($f); } function save() { '
    '$t = "uploads/" . basename($_FILES["up"]["name"]); move_uploaded_file($_FILES["up"]["tmp_name"], $t); }'))
check("raw client name is reported once (path-move-upload), not twice", snippet(
    '<?php move_uploaded_file($_FILES["up"]["tmp_name"], "uploads/" . $_FILES["up"]["name"]);') == ["path-move-upload"])
check("upload-unrestricted is high / CWE-434", RULES_BY_ID["upload-unrestricted"]["severity"] == "high"
      and RULES_BY_ID["upload-unrestricted"]["cwe"] == "CWE-434")

# 8. false positives
check("TLS verification off as a literal still fires", "tls-verify-disabled" in snippet(
    '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);'))
check("TLS verification off inside the caller's own option check stays quiet", snippet(
    '<?php if ($options["verify"] === false) { curl_setopt($h, CURLOPT_SSL_VERIFYHOST, 0); curl_setopt($h, CURLOPT_SSL_VERIFYPEER, 0); }') == [])
check("TLS verification from a variable stays quiet", snippet(
    '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verify);') == [])
check("... and fires again after the option block", "tls-verify-disabled" in snippet(
    '<?php if ($o["sslverify"]) { $x = 1; } curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);'))
EXT = ('<?php $name = $_FILES["up"]["name"]; $ext = substr($name, strrpos($name, ".") + 1); '
       '$tmp = sys_get_temp_dir() . "/" . md5(uniqid() . $name) . "." . $ext; ')
check("rename/unlink of random name + client extension stays quiet", snippet(
    EXT + 'if (!in_array($ext, ["jpg"], true)) { die(); } rename($tmp, getcwd() . "/up/" . md5($name) . "." . $ext); unlink($tmp);') == [])
check("pathinfo extension is not a traversal vector", snippet(
    '<?php $e = pathinfo($_GET["f"], PATHINFO_EXTENSION); unlink("cache/thumb." . $e);') == [])
check("... but the whole client path still is", "path-delete" in snippet('<?php unlink("cache/" . $_GET["f"]);'))
check("pathinfo without PATHINFO_EXTENSION keeps the taint", "path-delete" in snippet(
    '<?php $d = pathinfo($_GET["f"]); unlink($d["dirname"] . "/x");'))

check("a ternary condition chooses, it is not the value", snippet(
    '<?php $o = get_query_var("order"); $d = ("DESC" === $o); $l = $d ? next_link() : prev_link(); echo $l;') == [])
check("... but a tainted branch still is", "xss-echo" in snippet('<?php $l = $ok ? $_GET["a"] : "x"; echo $l;'))
check("short ternary keeps the tested value", "xss-echo" in snippet('<?php $l = $_GET["a"] ?: "x"; echo $l;'))
check("value authenticated with hash_equals before unserialize stays quiet", snippet(
    '<?php function load($v) { $d = base64_decode($v["data"]); if (!hash_equals(sign($d), $v["mac"])) { return null; } '
    'return unserialize($d); } load($_POST["w"]);') == [])
check("the same wrapper without the check is reported", "unserialize-tainted" in snippet(
    '<?php function load($v) { $d = base64_decode($v["data"]); return unserialize($d); } load($_POST["w"]);'))

# --- output formats ---------------------------------------------------------------------
s = code.to_sarif(vuln)
json.dumps(s)
run = s["runs"][0]
check("SARIF version 2.1.0", s["version"] == "2.1.0" and "$schema" in s)
check("SARIF driver rules == list_rules", len(run["tool"]["driver"]["rules"]) == len(code.list_rules()))
check("SARIF results count", len(run["results"]) == len(vuln["findings"]))
r0 = run["results"][0]
reg = r0["locations"][0]["physicalLocation"]["region"]
check("SARIF region startLine/startColumn", reg["startLine"] >= 1 and reg["startColumn"] >= 1)
check("SARIF ruleIndex consistent", run["tool"]["driver"]["rules"][r0["ruleIndex"]]["id"] == r0["ruleId"])
txt = code.to_text(vuln)
check("text output mentions rule and summary", "eval-tainted" in txt and "Summary:" in txt)
check("result shape", vuln["tool"] == "phpwarden-code" and vuln["files_scanned"] == 5 and
      set(vuln["summary"]) == {"critical", "high", "medium", "low"})
rl = code.list_rules()
check("~60+ rules with metadata", len(rl) >= 60 and all(r["cwe"].startswith("CWE-") and r["fix"] for r in rl))
check("rule ids unique", len({r["id"] for r in rl}) == len(rl))

# --- performance: 2,000 files -----------------------------------------------------------
d = tempfile.mkdtemp()
try:
    body = ("<?php\nnamespace App;\nclass C%d {\n  private $x;\n  public function a($r) {\n"
            "    $id = intval($_GET['id']);\n    $q = \"SELECT * FROM t WHERE id = $id\";\n"
            "    $rows = $this->db->query($q);\n    foreach ($rows as $row) { echo htmlspecialchars($row['n']); }\n"
            "    return array_map(function ($v) { return trim($v) . 'x'; }, $rows);\n  }\n") + \
           "".join("  public function m%d($a, $b) { $s = $a . '-' . $b; if ($s === 'x') { return [$a => $b]; } return strtoupper($s); }\n" % k
                   for k in range(30)) + "}\n"
    for i in range(2000):
        sub = os.path.join(d, "src", "m%02d" % (i % 40))
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, "C%d.php" % i), "w") as fh:
            fh.write(body % i)
    t = time.time()
    perf = code.scan_project(d)
    el = time.time() - t
    print("   2,000 files scanned in %.1fs" % el)
    check("perf: 2,000 files scanned", perf["files_scanned"] == 2000)
    check("perf: under 30 s", el < 30)
    check("perf: synthetic safe code has no findings", perf["findings"] == [])
finally:
    shutil.rmtree(d)

# --- cross-file (project-wide) taint -------------------------------------------
XF = code.scan_project(str(FIX / "crossfile"))
xf = {}
for f in XF["findings"]:
    xf.setdefault(f["file"], []).append(f)
def xrules(path):
    return {f["rule"] for f in xf.get(path, [])}
check("cross-file: helper class two levels deep (Repo -> Db -> query) reported at the call site",
      "sql-db-query" in xrules("pages/vuln_sql.php"))
check("cross-file: message names the function and its file",
      any("via findbyname() in lib/Repo.php:4" in f["message"] for f in xf.get("pages/vuln_sql.php", [])))
check("cross-file: same helper called with intval() or a literal stays quiet", xrules("pages/safe_sql.php") == set())
check("cross-file: function returning $_GET in one file used in system() in another",
      "cmd-system" in xrules("pages/vuln_cmd.php"))
check("cross-file: escapeshellarg() around that function's result stays quiet", xrules("pages/safe_cmd.php") == set())
# Engine-neutral: the flow may be reported at the include that uses the value
# (token engine) or where the included file reads the request (AST engine).
check("include: a variable set from the request in an included file controls a later include",
      "include-tainted" in xrules("pages/vuln_incl.php") or "include-tainted" in xrules("inc/page_from_request.php"))
check("include: the same pattern with a fixed value stays quiet", xrules("pages/safe_incl.php") == set())
check("property: set from $_POST in one method, used in SQL in another", "sql-mysqli-query" in xrules("classes/Search.php"))
check("property: an (int) cast before storing stays quiet", xrules("classes/SafeSearch.php") == set())
check("same function name with different behaviour in two files is skipped", xrules("pages/ambiguous.php") == set())
check("a four-level chain across four files does not crash or loop", isinstance(XF["files_scanned"], int)
      and XF["files_scanned"] == len(list((FIX / "crossfile").rglob("*.php"))))
check("library files themselves report nothing", not any(p.startswith("lib/") for p in xf))

def project(files, **kw):
    d = tempfile.mkdtemp()
    try:
        for name, php in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, name)), exist_ok=True)
            with open(os.path.join(d, name), "w") as fh:
                fh.write(php)
        return {(f["file"], f["rule"]) for f in code.scan_project(d, **kw)["findings"]}
    finally:
        shutil.rmtree(d)

check("cross-file wrapper of a wrapper (2 levels across 3 files)", ("p.php", "cmd-exec") in project({
    "a.php": '<?php function outer_run($c) { return inner_run($c); }',
    "b.php": '<?php function inner_run($c) { exec($c); }',
    "p.php": '<?php outer_run("ls " . $_GET["d"]);'}))
check("cross-file return pass-through: helper that trims its argument keeps the taint", ("p.php", "xss-echo") in project({
    "h.php": '<?php function clean_it($s) { return trim($s); }',
    "p.php": '<?php echo clean_it($_GET["q"]);'}))
check("cross-file return pass-through: helper that escapes its argument clears XSS", project({
    "h.php": '<?php function safe_out($s) { return htmlspecialchars($s, ENT_QUOTES); }',
    "p.php": '<?php echo safe_out($_GET["q"]);'}) == set())
check("cross-file: a helper returning $_SERVER['REQUEST_URI'] is not exported as request data", project({
    "h.php": '<?php function here_url() { return $_SERVER["REQUEST_URI"]; }',
    "p.php": '<?php system("x " . here_url());'}) == set())
check("cross-file: a helper that returns request data on only one path is not exported", project({
    "h.php": '<?php function maybe_param($k) { if (DEBUG) { return $_GET[$k]; } return "x"; }',
    "p.php": '<?php system("x " . maybe_param("a"));'}) == set())
check("method resolved by a unique name on any receiver", ("p.php", "sql-mysqli-query") in project({
    "m.php": '<?php class Store { function saveRaw($v) { mysqli_query($this->c, "INSERT INTO t VALUES (\'" . $v . "\')"); } }',
    "p.php": '<?php $s = new Store(); $s->saveRaw($_POST["v"]);'}))
check("method name defined in two classes is not resolved on an unknown receiver", project({
    "m1.php": '<?php class A1 { function store($v) { mysqli_query($this->c, "X" . $v); } }',
    "m2.php": '<?php class A2 { function store($v) { return 1; } }',
    "p.php": '<?php $s->store($_POST["v"]);'}) == set())
check("sanitiser behind an unrelated flag: the variable may still be tainted after the block",
      "sql-mysqli-query" in snippet('<?php $n = $_GET["n"]; if ($strict) { $n = intval($n); } mysqli_query($c, "SELECT $n");'))
check("... but inside that block it is clean", snippet(
    '<?php $n = $_GET["n"]; if ($strict) { $n = intval($n); mysqli_query($c, "SELECT $n"); }') == [])
check("for-loop initialiser resets the variable", snippet(
    '<?php $i = $_GET["i"]; for ($i = 0; $i < 3; $i++) { echo $i; }') == [])
check("validate_file() !== 0 with an early return guards a path", snippet(
    '<?php $f = $_GET["f"]; if (0 !== validate_file($f)) { return; } readfile($f);') == [])
check("a nonce bound to the exact value authenticates it", snippet(
    '<?php $p = $_REQUEST["plugin"]; check_admin_referer("activate-plugin_" . $p); include WP_PLUGIN_DIR . "/" . $p;') == [])
check("$file['tmp_name'] of an upload is not client-controlled", snippet(
    '<?php $file = $_FILES["up"]; readfile($file["tmp_name"]);') == [])

print("RESULT: ALL PASS" if ok else "RESULT: FAILURES")
sys.exit(0 if ok else 1)
