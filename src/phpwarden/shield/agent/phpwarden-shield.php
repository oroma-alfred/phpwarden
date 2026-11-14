<?php
/**
 * phpwarden shield: inside-PHP protection for the vulnerabilities a site actually has.
 *
 * Load it before the application, with php.ini / .user.ini:
 *     auto_prepend_file = /path/to/phpwarden-shield.php
 * or as the first line of index.php / wp-config.php:
 *     require '/path/to/phpwarden-shield.php';
 *
 * It reads a policy built by `phpwarden shield policy` (rules only for the
 * exploited vulnerabilities installed on this site) and checks each request
 * before the application runs.
 *
 *   - mode "log" (the default): matches are written to a log; nothing is blocked.
 *   - a rule blocks only when the policy is in "enforce" mode AND that rule was
 *     promoted after a burn-in (`phpwarden shield promote`).
 *   - it fails open: any error (missing or malformed policy, an exception, the
 *     time budget running out) lets the request through untouched.
 *   - kill switch: a file named phpwarden-shield.off next to this file, or the
 *     environment variable PHPWARDEN_SHIELD=off, turns it off immediately.
 *
 * Policy location: env PHPWARDEN_SHIELD_POLICY, else phpwarden-shield.policy.php
 * (preferred: cached by opcache) or phpwarden-shield.policy.json next to this file.
 *
 * PHP 7.4 - 8.x, no extensions. Apache-2.0. https://phpwarden.io/docs#shield
 */

if (!function_exists('phpwarden_shield_run')) {

function phpwarden_shield_run()
{
    $dir = __DIR__;
    if (getenv('PHPWARDEN_SHIELD') === 'off' || is_file($dir . '/phpwarden-shield.off')) {
        return;
    }
    $t0 = microtime(true);
    $policy = phpwarden_shield_policy($dir);
    if (!is_array($policy) || empty($policy['rules']) || !is_array($policy['rules'])) {
        return;
    }
    $budget = (isset($policy['budget_ms']) ? (float)$policy['budget_ms'] : 5.0) / 1000.0;
    $req = phpwarden_shield_request($policy);
    $enforce = isset($policy['mode']) && $policy['mode'] === 'enforce';
    $hits = array();
    $block = null;
    foreach ($policy['rules'] as $rule) {
        if ((microtime(true) - $t0) > $budget) {
            $hits[] = array('rule' => '_budget', 'cve' => null, 'where' => '', 'excerpt' => '', 'action' => 'skip');
            break;                                            // fail open: out of time
        }
        $m = phpwarden_shield_match($rule, $req);
        if ($m === null) {
            continue;
        }
        $action = ($enforce && isset($rule['mode']) && $rule['mode'] === 'block') ? 'block' : 'log';
        $hits[] = array('rule' => (string)$rule['id'], 'cve' => isset($rule['cve']) ? $rule['cve'] : null,
                        'where' => $m[0], 'excerpt' => $m[1], 'action' => $action);
        if ($action === 'block') {
            $block = $rule;
            break;
        }
    }
    if ($hits) {
        phpwarden_shield_log($policy, $dir, $req, $hits);
    }
    if ($block !== null) {
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo "<!doctype html><title>Request blocked</title><body style=\"font:16px sans-serif;margin:40px\">"
           . "<h1 style=\"font-size:20px\">This request was blocked</h1>"
           . "<p>It matched a protection rule for a known vulnerability on this site. If you think this is a mistake, "
           . "contact the site owner.</p></body>";
        exit;
    }
}

function phpwarden_shield_policy($dir)
{
    $p = getenv('PHPWARDEN_SHIELD_POLICY');
    $candidates = $p ? array($p) : array($dir . '/phpwarden-shield.policy.php', $dir . '/phpwarden-shield.policy.json');
    foreach ($candidates as $f) {
        if (!is_file($f) || !is_readable($f)) {
            continue;
        }
        if (substr($f, -4) === '.php') {
            $pol = include $f;                                // opcache-cached
        } else {
            $raw = @file_get_contents($f, false, null, 0, 2000000);
            $pol = $raw === false ? null : json_decode($raw, true);
        }
        return is_array($pol) ? $pol : null;
    }
    return null;
}

function phpwarden_shield_request($policy)
{
    $uri = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '/';
    $q = strpos($uri, '?');
    $path = $q === false ? $uri : substr($uri, 0, $q);
    $query = isset($_SERVER['QUERY_STRING']) ? (string)$_SERVER['QUERY_STRING'] : ($q === false ? '' : substr($uri, $q + 1));
    $params = array();
    $names = array();
    phpwarden_shield_flatten($_GET, '', $params, $names, 0);
    phpwarden_shield_flatten($_POST, '', $params, $names, 0);
    $headers = array();
    foreach ($_SERVER as $k => $v) {
        if (strncmp($k, 'HTTP_', 5) === 0 && is_string($v)) {
            $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = $v;
        }
    }
    if (isset($_SERVER['CONTENT_TYPE'])) {
        $headers['content-type'] = (string)$_SERVER['CONTENT_TYPE'];
    }
    $ip = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
    if (!empty($policy['trust_proxy']) && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim(end($parts));
    }
    return array(
        'method' => isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string)$_SERVER['REQUEST_METHOD']) : 'GET',
        'path' => $path, 'query' => $query, 'params' => $params, 'names' => $names,
        'cookies' => is_array($_COOKIE) ? $_COOKIE : array(), 'headers' => $headers, 'ip' => $ip,
        'body' => null,                                        // read lazily, only if a rule needs it
    );
}

function phpwarden_shield_flatten($arr, $prefix, &$params, &$names, $depth)
{
    if (!is_array($arr) || $depth > 4) {
        return;
    }
    foreach ($arr as $k => $v) {
        if (count($params) >= 300) {
            return;
        }
        $k = (string)$k;
        $names[] = $k;
        $name = $prefix === '' ? $k : $prefix . '[' . $k . ']';
        if (is_array($v)) {
            phpwarden_shield_flatten($v, $name, $params, $names, $depth + 1);
        } else {
            $params[] = array($name, substr((string)$v, 0, 8192));
        }
    }
}

function phpwarden_shield_body(&$req)
{
    if ($req['body'] === null) {
        $req['body'] = '';
        $ct = isset($req['headers']['content-type']) ? strtolower($req['headers']['content-type']) : '';
        $len = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
        if ($len > 0 && strpos($ct, 'multipart/') !== 0) {
            $b = @file_get_contents('php://input', false, null, 0, 65536);
            $req['body'] = $b === false ? '' : $b;
        }
    }
    return $req['body'];
}

function phpwarden_shield_rx($re)
{
    return "\x01" . $re . "\x01is";
}

/** Returns [where, excerpt] when the rule matches, else null. */
function phpwarden_shield_match($rule, &$req)
{
    if (!empty($rule['method']) && is_array($rule['method']) && !in_array($req['method'], array_map('strtoupper', $rule['method']), true)) {
        return null;
    }
    if (!empty($rule['path']) && !@preg_match(phpwarden_shield_rx($rule['path']), $req['path'])) {
        return null;
    }
    $first = array('path', $req['path']);
    $conds = isset($rule['all']) && is_array($rule['all']) ? $rule['all'] : array();
    foreach ($conds as $i => $c) {
        $hit = phpwarden_shield_cond($c, $req);
        if ($hit === null) {
            return null;
        }
        if ($i === 0) {
            $first = $hit;
        }
    }
    return array($first[0], phpwarden_shield_redact($first[0], $first[1]));
}

function phpwarden_shield_cond($c, &$req)
{
    $in = isset($c['in']) ? $c['in'] : '';
    $name = isset($c['name']) ? (string)$c['name'] : '*';
    $rx = isset($c['re']) && $c['re'] !== '' ? phpwarden_shield_rx($c['re']) : null;
    $test = function ($where, $v) use ($rx) {
        if (!is_string($v) || $v === '') {
            return null;
        }
        if ($rx === null) {
            return array($where, $v);
        }
        return @preg_match($rx, $v, $m) ? array($where, $v) : null;
    };
    if ($in === 'path' || $in === 'query') {
        return $test($in, $req[$in]);
    }
    if ($in === 'body') {
        return $test('body', phpwarden_shield_body($req));
    }
    if ($in === 'param') {
        $found = false;
        foreach ($req['params'] as $p) {
            if ($name !== '*' && $p[0] !== $name && strpos($p[0], $name . '[') !== 0) {
                continue;
            }
            $found = true;
            if ($rx === null) {
                return array('param:' . $p[0], $p[1]);
            }
            $h = $test('param:' . $p[0], $p[1]);
            if ($h) {
                return $h;
            }
        }
        return null;
    }
    if ($in === 'param_name') {
        foreach ($req['names'] as $n) {
            if ($rx === null || @preg_match($rx, $n)) {
                return array('param_name', $n);
            }
        }
        foreach ($req['params'] as $p) {                      // raw keys (e.g. mail[#post_render][])
            if ($rx !== null && @preg_match($rx, $p[0])) {
                return array('param_name', $p[0]);
            }
        }
        return null;
    }
    if ($in === 'cookie') {
        foreach ($req['cookies'] as $k => $v) {
            if ($name !== '*' && (string)$k !== $name) {
                continue;
            }
            if (!is_string($v)) {
                $v = json_encode($v);
            }
            if ($rx === null) {
                return array('cookie:' . $k, (string)$v);
            }
            $h = $test('cookie:' . $k, $v);
            if ($h) {
                return $h;
            }
        }
        return null;
    }
    if ($in === 'header') {
        $k = strtolower($name);
        if (!isset($req['headers'][$k])) {
            return null;
        }
        return $rx === null ? array('header:' . $k, $req['headers'][$k]) : $test('header:' . $k, $req['headers'][$k]);
    }
    if ($in === 'any' || $in === 'any_or_path') {
        foreach ($req['params'] as $p) {
            $h = $test('param:' . $p[0], $p[1]);
            if ($h) {
                return $h;
            }
        }
        foreach ($req['cookies'] as $k => $v) {
            $h = $test('cookie:' . $k, is_string($v) ? $v : json_encode($v));
            if ($h) {
                return $h;
            }
        }
        $h = $test('body', phpwarden_shield_body($req));
        if ($h) {
            return $h;
        }
        if ($in === 'any_or_path') {
            foreach (array(array('path', $req['path']), array('query', $req['query']), array('path', urldecode($req['path']))) as $pv) {
                $h = $test($pv[0], $pv[1]);
                if ($h) {
                    return $h;
                }
            }
        }
        return null;
    }
    return null;
}

/** A short excerpt with secrets masked: never a full body or a credential. */
function phpwarden_shield_redact($where, $v)
{
    if (preg_match('/(pass|pwd|token|secret|key|auth|session|cookie|nonce|hash)/i', $where)) {
        return '[redacted]';
    }
    $v = preg_replace('/[A-Za-z0-9+\/=_-]{33,}/', '[long value]', (string)$v);
    $v = preg_replace('/[\x00-\x1f\x7f]/', '?', $v);
    if (strlen($v) > 120) {
        $v = substr($v, 0, 120) . '...';
    }
    return $v;
}

function phpwarden_shield_log($policy, $dir, $req, $hits)
{
    $file = isset($policy['log']['path']) && $policy['log']['path'] ? $policy['log']['path'] : $dir . '/phpwarden-shield.log';
    $max = isset($policy['log']['max_bytes']) ? (int)$policy['log']['max_bytes'] : 5000000;
    clearstatcache(true, $file);
    if ($max > 0 && @filesize($file) > $max) {
        @rename($file, $file . '.1');                         // keep one previous file
    }
    $out = '';
    $now = gmdate('Y-m-d\TH:i:s\Z');
    foreach ($hits as $h) {
        $out .= json_encode(array(
            'ts' => $now, 'rule' => $h['rule'], 'cve' => $h['cve'], 'action' => $h['action'],
            'method' => $req['method'], 'path' => substr($req['path'], 0, 300), 'where' => $h['where'],
            'excerpt' => $h['excerpt'], 'ip' => $req['ip'],
        ), JSON_UNESCAPED_SLASHES) . "\n";
    }
    @file_put_contents($file, $out, FILE_APPEND | LOCK_EX);
}

}

try {
    $__pw_prev = set_error_handler(function () { return true; });
    phpwarden_shield_run();
} catch (\Throwable $__pw_e) {
    // fail open: never break the site
} finally {
    restore_error_handler();
}
unset($__pw_prev, $__pw_e);
