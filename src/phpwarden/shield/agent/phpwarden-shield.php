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
 *   - rate limits (policy "limits"): per-client sliding windows on login,
 *     xmlrpc, password-reset and other sensitive endpoints, plus a burst guard
 *     on rule-scoped paths. Same modes as rules: logged by default, 429 only
 *     when the policy enforces and the limit was promoted. Counters live in
 *     APCu or a small file store; if neither works, limits switch off (fail open).
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
    if (!is_array($policy)) {
        return;
    }
    $rules = isset($policy['rules']) && is_array($policy['rules']) ? $policy['rules'] : array();
    $limits = isset($policy['limits']) && is_array($policy['limits']) ? $policy['limits'] : array();
    if (!$rules && !$limits) {
        return;
    }
    $budget = (isset($policy['budget_ms']) ? (float)$policy['budget_ms'] : 5.0) / 1000.0;
    $req = phpwarden_shield_request($policy);
    $enforce = isset($policy['mode']) && $policy['mode'] === 'enforce';
    $hits = array();
    $block = null;
    foreach ($rules as $rule) {
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
    $limited = null;
    if ($block === null && $limits && (microtime(true) - $t0) <= $budget) {
        $limited = phpwarden_shield_limits($policy, $limits, $dir, $req, $enforce, $hits);
    }
    if ($hits) {
        phpwarden_shield_log($policy, $dir, $req, $hits);
    }
    if ($limited !== null) {
        if (!headers_sent()) {
            http_response_code(429);
            header('Retry-After: ' . (int)$limited);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store');
        }
        echo "Too many requests. Please wait and try again.\n";
        exit;
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
    $ip = phpwarden_shield_client_ip($policy);
    // original names of uploaded files (multipart bodies are not read as text)
    $files = array();
    if (!empty($_FILES) && is_array($_FILES)) {
        // field[a][b] uploads nest the names: $_FILES['field']['name']['a']['b']
        foreach ($_FILES as $f) {
            if (!is_array($f) || !isset($f['name'])) {
                continue;
            }
            $names = is_array($f['name']) ? $f['name'] : array($f['name']);
            array_walk_recursive($names, function ($v) use (&$files) {
                if (is_string($v) && $v !== '' && count($files) < 50) {
                    $files[] = $v;
                }
            });
        }
    }
    return array(
        'method' => isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string)$_SERVER['REQUEST_METHOD']) : 'GET',
        'path' => $path, 'query' => $query, 'params' => $params, 'names' => $names,
        'cookies' => is_array($_COOKIE) ? $_COOKIE : array(), 'headers' => $headers, 'ip' => $ip,
        'body' => null,                                        // read lazily, only if a rule needs it
        'files' => $files,
    );
}

/**
 * Client IP. REMOTE_ADDR, unless the peer is inside a CIDR listed in
 * policy "trust_proxy" (a list; a bare true trusts nothing). Then
 * CF-Connecting-IP, else the right-most X-Forwarded-For entry that is not
 * itself a trusted proxy. Spoofed headers from anyone else are ignored.
 */
function phpwarden_shield_client_ip($policy)
{
    $ip = isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '';
    $trusted = isset($policy['trust_proxy']) && is_array($policy['trust_proxy']) ? $policy['trust_proxy'] : array();
    if (!$trusted || !phpwarden_shield_in_cidrs($ip, $trusted)) {
        return $ip;
    }
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $cf = trim((string)$_SERVER['HTTP_CF_CONNECTING_IP']);
        if (@inet_pton($cf) !== false) {
            return $cf;
        }
    }
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = array_reverse(explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']));
        foreach ($parts as $p) {
            $p = trim($p);
            if (@inet_pton($p) === false) {
                break;
            }
            $ip = $p;
            if (!phpwarden_shield_in_cidrs($p, $trusted)) {
                break;
            }
        }
    }
    return $ip;
}

function phpwarden_shield_in_cidrs($ip, $cidrs)
{
    $bin = @inet_pton($ip);
    if ($bin === false) {
        return false;
    }
    foreach ($cidrs as $c) {
        $c = (string)$c;
        $slash = strpos($c, '/');
        $net = @inet_pton($slash === false ? $c : substr($c, 0, $slash));
        if ($net === false || strlen($net) !== strlen($bin)) {
            continue;
        }
        $bits = $slash === false ? strlen($bin) * 8 : (int)substr($c, $slash + 1);
        $bytes = intdiv($bits, 8);
        if (substr($bin, 0, $bytes) !== substr($net, 0, $bytes)) {
            continue;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rem)) & 0xff;
        if ((ord($bin[$bytes]) & $mask) === (ord($net[$bytes]) & $mask)) {
            return true;
        }
    }
    return false;
}

/**
 * Rate limits. Each limit: name, method[], path (regex), all[] (same conditions
 * as rules), max, window_s, kind ("client": per IP; "burst": per IP and path),
 * mode ("log" | "block"). Sliding window approximated with two fixed buckets.
 * Returns Retry-After seconds when a promoted limit is exceeded in enforce
 * mode, else null. Appends log entries to $hits (counts, never bodies).
 */
function phpwarden_shield_limits($policy, $limits, $dir, &$req, $enforce, &$hits)
{
    if ($req['ip'] === '') {
        return null;
    }
    $store = phpwarden_shield_store($policy, $dir);
    if ($store === null) {
        return null;                                          // fail open
    }
    $now = time();
    $retry = null;
    foreach ($limits as $lim) {
        if (!is_array($lim) || empty($lim['name']) || phpwarden_shield_match($lim, $req) === null) {
            continue;
        }
        $max = isset($lim['max']) ? max(1, (int)$lim['max']) : 10;
        $win = isset($lim['window_s']) ? max(1, (int)$lim['window_s']) : 60;
        $key = $lim['name'] . '|' . $req['ip'] . ((isset($lim['kind']) && $lim['kind'] === 'burst') ? '|' . $req['path'] : '');
        $n = phpwarden_shield_count($store, $key, $win, $now);
        if ($n === null) {
            return null;
        }
        if ($n[0] <= $max) {
            continue;
        }
        $action = ($enforce && isset($lim['mode']) && $lim['mode'] === 'block') ? 'block' : 'log';
        $hits[] = array('rule' => 'limit:' . $lim['name'], 'cve' => null, 'where' => 'rate',
                        'excerpt' => $n[0] . ' in ' . $win . 's (max ' . $max . ')', 'action' => $action);
        if ($action === 'block') {
            $retry = max(1, $n[1]);
            break;
        }
    }
    return $retry;
}

/** Returns ['apcu'] or ['file', dir, max_files], or null when no store works (logged once). */
function phpwarden_shield_store($policy, $dir)
{
    $cfg = isset($policy['limits_store']) && is_array($policy['limits_store']) ? $policy['limits_store'] : array();
    $want = isset($cfg['backend']) ? (string)$cfg['backend'] : 'auto';
    if ($want !== 'file' && function_exists('apcu_enabled') && apcu_enabled()) {
        return array('apcu');
    }
    $d = isset($cfg['dir']) && $cfg['dir'] ? (string)$cfg['dir'] : $dir . '/phpwarden-shield.limits';
    if (!is_dir($d)) {
        @mkdir($d, 0700, true);
    }
    if (is_dir($d) && is_writable($d)) {
        return array('file', $d, isset($cfg['max_files']) ? max(100, (int)$cfg['max_files']) : 20000);
    }
    $logf = isset($policy['log']['path']) && $policy['log']['path'] ? $policy['log']['path'] : $dir . '/phpwarden-shield.log';
    $mark = $logf . '.nostore';
    if (!is_file($mark)) {
        @touch($mark);
        @file_put_contents($logf, json_encode(array('ts' => gmdate('Y-m-d\TH:i:s\Z'), 'rule' => 'limit:_store_unavailable',
            'cve' => null, 'action' => 'skip', 'method' => '', 'path' => '', 'where' => '', 'excerpt' => 'limits disabled: no APCu and store dir not writable', 'ip' => ''),
            JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
    }
    return null;
}

/** Increment and return [estimated count in the sliding window, seconds until it frees up]. */
function phpwarden_shield_count($store, $key, $win, $now)
{
    $start = $now - ($now % $win);
    $k = 'pwsl:' . sha1($key);
    if ($store[0] === 'apcu') {
        $v = apcu_fetch($k);
        $st = phpwarden_shield_bump(is_array($v) ? $v : null, $start, $win);
        apcu_store($k, $st, 2 * $win + 1);
    } else {
        $f = $store[1] . '/' . substr($k, 5, 40);
        $h = @fopen($f, 'c+');
        if ($h === false) {
            return null;
        }
        if (!@flock($h, LOCK_EX)) {
            fclose($h);
            return null;
        }
        $raw = stream_get_contents($h);
        $v = $raw ? array_map('intval', explode(' ', trim($raw))) : null;
        $st = phpwarden_shield_bump(is_array($v) && count($v) === 3 ? $v : null, $start, $win);
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, implode(' ', $st));
        flock($h, LOCK_UN);
        fclose($h);
        if (mt_rand(1, 200) === 1) {
            phpwarden_shield_prune($store[1], $store[2], $now);
        }
    }
    $elapsed = $now - $start;
    $est = (int)floor($st[2] * (($win - $elapsed) / $win)) + $st[1];
    return array($est, $win - $elapsed);
}

/** State [bucket_start, current, previous]. */
function phpwarden_shield_bump($v, $start, $win)
{
    if ($v === null || $v[0] < $start - $win) {
        return array($start, 1, 0);
    }
    if ($v[0] < $start) {
        return array($start, 1, $v[1]);
    }
    return array($v[0], $v[1] + 1, $v[2]);
}

/** Bound the file store: drop counters untouched for an hour, then the oldest past max_files. */
function phpwarden_shield_prune($d, $maxFiles, $now)
{
    $files = @scandir($d);
    if (!is_array($files)) {
        return;
    }
    $keep = array();
    foreach ($files as $f) {
        if (strlen($f) !== 40) {
            continue;
        }
        $m = @filemtime($d . '/' . $f);
        if ($m !== false && $m < $now - 3600) {
            @unlink($d . '/' . $f);
        } elseif ($m !== false) {
            $keep[$f] = $m;
        }
    }
    if (count($keep) > $maxFiles) {
        asort($keep);
        foreach (array_slice(array_keys($keep), 0, count($keep) - $maxFiles) as $f) {
            @unlink($d . '/' . $f);
        }
    }
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
    if ($in === 'file_name') {
        foreach ($req['files'] as $fn) {
            $h = $rx === null ? array('file_name', $fn) : $test('file_name', $fn);
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
