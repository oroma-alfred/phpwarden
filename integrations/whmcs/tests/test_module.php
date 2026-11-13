<?php
/**
 * Dependency-free tests for the phpwarden WHMCS module.
 * Run: php integrations/whmcs/tests/test_module.php
 */

error_reporting(E_ALL);
define('WHMCS', true);

const KEY = 'pwp_SECRETPARTNERKEY123';

$LOGS = array();      // every logModuleCall
$LOCAL = array();     // every localAPI call
$HTTP = array();      // every HTTP request
$ROUTES = array();    // "METHOD /path" => array(status, body array|string) or callable

function logModuleCall($module, $action, $request, $response, $processed = '', $replace = array())
{
    $GLOBALS['LOGS'][] = func_get_args();
}

function localAPI($command, $values = array(), $admin = null)
{
    $GLOBALS['LOCAL'][] = array($command, $values);
    return array('result' => $GLOBALS['LOCAL_RESULT']);
}

require __DIR__ . '/../modules/servers/phpwarden/phpwarden.php';

$GLOBALS['phpwarden_transport'] = function ($method, $url, $headers, $body) {
    $path = (string) parse_url($url, PHP_URL_PATH);
    $GLOBALS['HTTP'][] = array(
        'method' => $method, 'url' => $url, 'path' => $path,
        'headers' => $headers, 'body' => $body === null ? null : json_decode($body, true),
    );
    $route = $method . ' ' . $path;
    if (!isset($GLOBALS['ROUTES'][$route])) {
        return array('status' => 404, 'body' => '{"error":"not_found"}');
    }
    $r = $GLOBALS['ROUTES'][$route];
    if (is_callable($r)) {
        $r = $r();
    }
    return array('status' => $r[0], 'body' => is_string($r[1]) ? $r[1] : json_encode($r[1]));
};

$GLOBALS['phpwarden_field_lookup'] = function ($pid) {
    return $GLOBALS['FIELDS'];
};

// --- tiny harness ----------------------------------------------------------

$PASS = 0;
$FAIL = 0;

function ok($cond, $label)
{
    if ($cond) {
        $GLOBALS['PASS']++;
        echo "  ok   $label\n";
    } else {
        $GLOBALS['FAIL']++;
        echo "  FAIL $label\n";
    }
}

function same($expected, $actual, $label)
{
    ok($expected === $actual, $label . ($expected === $actual ? '' : ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ')'));
}

function reset_world()
{
    $GLOBALS['LOGS'] = array();
    $GLOBALS['LOCAL'] = array();
    $GLOBALS['HTTP'] = array();
    $GLOBALS['ROUTES'] = array();
    $GLOBALS['LOCAL_RESULT'] = 'success';
    $GLOBALS['FIELDS'] = array('phpwarden Project ID' => 11, 'phpwarden Token' => 12);
}

function params(array $over = array())
{
    return array_merge(array(
        'serviceid' => 42,
        'pid' => 7,
        'domain' => 'example.com',
        'serveraccesshash' => '',
        'serverpassword' => KEY,
        'serverhostname' => '',
        'configoption1' => 'https://app.phpwarden.io',
        'customfields' => array('phpwarden Project ID' => '', 'phpwarden Token' => ''),
    ), $over);
}

function stored()
{
    $out = array();
    foreach ($GLOBALS['LOCAL'] as $call) {
        $out[] = array($call[0], $call[1]['serviceid'], unserialize(base64_decode($call[1]['customfields'])));
    }
    return $out;
}

/** Everything written to the log except the replacevars argument. */
function logged_text()
{
    $text = '';
    foreach ($GLOBALS['LOGS'] as $l) {
        $text .= json_encode(array_slice($l, 0, 5)) . "\n";
    }
    return $text;
}

$withIds = params(array('customfields' => array('phpwarden Project ID' => 'p_1', 'phpwarden Token' => 'tok_old')));

// --- tests -----------------------------------------------------------------

echo "metadata and config\n";
$m = phpwarden_MetaData();
same('phpwarden', $m['DisplayName'], 'display name');
same('1.1', (string) $m['APIVersion'], 'api version');
same(true, $m['RequiresServer'], 'requires server');
$c = phpwarden_ConfigOptions();
same('https://app.phpwarden.io', $c['API base URL']['Default'], 'default base url');

echo "create: new project\n";
reset_world();
$ROUTES['POST /v1/partner/projects'] = array(201, array(
    'id' => 'p_1', 'name' => 'example.com', 'external_id' => 'whmcs-42',
    'token' => 'tok_NEWSECRET', 'dashboard_url' => 'https://app.phpwarden.io/p/p_1',
));
same('success', phpwarden_CreateAccount(params()), 'returns success');
same(1, count($HTTP), 'one HTTP call');
same('POST', $HTTP[0]['method'], 'method POST');
same('https://app.phpwarden.io/v1/partner/projects', $HTTP[0]['url'], 'url');
same(array('name' => 'example.com', 'external_id' => 'whmcs-42'), $HTTP[0]['body'], 'body');
ok(in_array('Authorization: Bearer ' . KEY, $HTTP[0]['headers'], true), 'bearer auth sent');
ok(in_array('Content-Type: application/json', $HTTP[0]['headers'], true), 'json content type');
same(array(array('UpdateClientProduct', 42, array(11 => 'p_1', 12 => 'tok_NEWSECRET'))), stored(), 'id and token stored');
ok(strpos(logged_text(), KEY) === false, 'key not in log');
ok(strpos(logged_text(), 'tok_NEWSECRET') === false, 'token not in log');
ok(in_array(KEY, $LOGS[0][5], true) && in_array('tok_NEWSECRET', $LOGS[0][5], true), 'key and token passed as replacevars');
same('phpwarden', $LOGS[0][0], 'log module name');

echo "create: name fallback and access hash precedence\n";
reset_world();
$ROUTES['POST /v1/partner/projects'] = array(201, array('id' => 'p_2', 'token' => 't2'));
same('success', phpwarden_CreateAccount(params(array('domain' => '', 'serveraccesshash' => 'pwp_HASHKEY'))), 'success');
same('service-42', $HTTP[0]['body']['name'], 'name falls back to service-<id>');
ok(in_array('Authorization: Bearer pwp_HASHKEY', $HTTP[0]['headers'], true), 'access hash wins over password');

echo "create: idempotent, token field empty -> rotate\n";
reset_world();
$ROUTES['POST /v1/partner/projects'] = array(200, array('id' => 'p_1', 'name' => 'example.com', 'external_id' => 'whmcs-42'));
$ROUTES['POST /v1/partner/projects/p_1/token'] = array(200, array('token' => 'tok_ROTATED'));
same('success', phpwarden_CreateAccount(params()), 'success');
same(array('/v1/partner/projects', '/v1/partner/projects/p_1/token'), array_column($HTTP, 'path'), 'create then rotate');
same(array(array('UpdateClientProduct', 42, array(11 => 'p_1', 12 => 'tok_ROTATED'))), stored(), 'id and rotated token stored');
ok(strpos(logged_text(), 'tok_ROTATED') === false, 'rotated token not in log');

echo "create: idempotent, token already stored -> no rotate\n";
reset_world();
$ROUTES['POST /v1/partner/projects'] = array(200, array('id' => 'p_1', 'external_id' => 'whmcs-42'));
same('success', phpwarden_CreateAccount($withIds), 'success');
same(1, count($HTTP), 'no rotate call');
same(array(array('UpdateClientProduct', 42, array(11 => 'p_1'))), stored(), 'only id rewritten, token kept');

echo "create: custom fields missing\n";
reset_world();
$FIELDS = array();
$ROUTES['POST /v1/partner/projects'] = array(200, array('id' => 'p_1'));
same('success', phpwarden_CreateAccount(params()), 'success');
same(1, count($HTTP), 'no rotate when there is no token field');
same(0, count($LOCAL), 'nothing written');

echo "lifecycle paths\n";
foreach (array(
    array('phpwarden_SuspendAccount', 'POST', '/v1/partner/projects/p_1/suspend', array('ok' => true, 'suspended' => true)),
    array('phpwarden_UnsuspendAccount', 'POST', '/v1/partner/projects/p_1/unsuspend', array('ok' => true, 'suspended' => false)),
    array('phpwarden_TerminateAccount', 'DELETE', '/v1/partner/projects/p_1', array('ok' => true)),
) as $case) {
    reset_world();
    $ROUTES[$case[1] . ' ' . $case[2]] = array(200, $case[3]);
    same('success', $case[0]($withIds), $case[0] . ' success');
    same(1, count($HTTP), $case[0] . ' one call');
    same($case[1] . ' ' . $case[2], $HTTP[0]['method'] . ' ' . $HTTP[0]['path'], $case[0] . ' method and path');
    same(null, $HTTP[0]['body'], $case[0] . ' no body');
}
same(array(array('UpdateClientProduct', 42, array(11 => '', 12 => ''))), stored(), 'terminate clears the custom fields');

echo "lookup by external_id when the field is empty\n";
reset_world();
$ROUTES['GET /v1/partner/projects'] = array(200, array('projects' => array(
    array('id' => 'p_other', 'external_id' => 'whmcs-420'),
    array('id' => 'p_9', 'external_id' => 'whmcs-42'),
)));
$ROUTES['POST /v1/partner/projects/p_9/suspend'] = array(200, array('ok' => true, 'suspended' => true));
same('success', phpwarden_SuspendAccount(params()), 'suspend success');
same(array('/v1/partner/projects', '/v1/partner/projects/p_9/suspend'), array_column($HTTP, 'path'), 'list then suspend the matching project');

reset_world();
$ROUTES['GET /v1/partner/projects'] = array(200, array('projects' => array()));
$r = phpwarden_SuspendAccount(params());
ok(is_string($r) && $r !== 'success', 'suspend with no project returns an error string');
same('success', phpwarden_TerminateAccount(params()), 'terminate with no project is a no-op success');

reset_world();
$ROUTES['DELETE /v1/partner/projects/p_1'] = array(404, array('error' => 'not_found'));
same('success', phpwarden_TerminateAccount($withIds), 'terminate of an already deleted project succeeds');

echo "errors are strings, never exceptions\n";
$errors = array(
    array(401, array('error' => 'invalid_key')),
    array(402, array('error' => 'plan_limit')),
    array(500, '<html>oops</html>'),
    array(200, 'not json'),
);
foreach ($errors as $e) {
    reset_world();
    $ROUTES['POST /v1/partner/projects'] = $e;
    $r = phpwarden_CreateAccount(params());
    ok(is_string($r) && $r !== 'success' && $r !== '', 'create HTTP ' . $e[0] . ' -> "' . $r . '"');
    ok(strpos($r, KEY) === false, 'error string has no key');
    same(0, count($LOCAL), 'nothing stored on error');
}

reset_world();
$ROUTES['POST /v1/partner/projects'] = function () {
    throw new RuntimeException('connect failed for Bearer ' . KEY);
};
$r = phpwarden_CreateAccount(params());
ok(is_string($r) && $r !== 'success', 'transport exception -> string');
ok(strpos($r, KEY) === false, 'key scrubbed from transport error');
ok(strpos(logged_text(), KEY) === false, 'key scrubbed from logged transport error');

reset_world();
$r = phpwarden_CreateAccount(params(array('serverpassword' => '')));
ok(is_string($r) && $r !== 'success', 'missing key -> error string');
same(0, count($HTTP), 'no request without a key');

reset_world();
$r = phpwarden_CreateAccount(params(array('configoption1' => 'http://evil.example')));
ok(is_string($r) && $r !== 'success', 'plain http base url refused');
same(0, count($HTTP), 'no request to a plain http host');

reset_world();
$LOCAL_RESULT = 'error';
$ROUTES['POST /v1/partner/projects'] = array(201, array('id' => 'p_1', 'token' => 't'));
$r = phpwarden_CreateAccount(params());
ok(is_string($r) && $r !== 'success', 'localAPI failure -> error string');

foreach (array('phpwarden_SuspendAccount', 'phpwarden_UnsuspendAccount', 'phpwarden_TerminateAccount', 'phpwarden_RotateToken') as $fn) {
    reset_world();
    $ROUTES['POST /v1/partner/projects/p_1/suspend'] = array(500, '');
    $ROUTES['POST /v1/partner/projects/p_1/unsuspend'] = array(500, '');
    $ROUTES['POST /v1/partner/projects/p_1/token'] = array(500, '');
    $ROUTES['DELETE /v1/partner/projects/p_1'] = array(500, '');
    $r = $fn($withIds);
    ok(is_string($r) && $r !== 'success', $fn . ' HTTP 500 -> error string');
}

echo "test connection\n";
reset_world();
$ROUTES['GET /v1/partner/projects'] = array(200, array('projects' => array()));
$r = phpwarden_TestConnection(array('serverpassword' => KEY, 'serverhostname' => 'app.phpwarden.io'));
same(array('success' => true, 'error' => ''), $r, 'success on 200');
same('https://app.phpwarden.io/v1/partner/projects', $HTTP[0]['url'], 'uses the server hostname');
same('GET', $HTTP[0]['method'], 'GET');
reset_world();
$ROUTES['GET /v1/partner/projects'] = array(401, array('error' => 'invalid_key'));
$r = phpwarden_TestConnection(array('serverpassword' => KEY));
ok($r['success'] === false && $r['error'] !== '', 'failure on 401');
same('https://app.phpwarden.io/v1/partner/projects', $HTTP[0]['url'], 'default base without hostname');

echo "rotate token button\n";
same(array('Rotate token' => 'RotateToken'), phpwarden_AdminCustomButtonArray(), 'button array');
reset_world();
$ROUTES['POST /v1/partner/projects/p_1/token'] = array(200, array('token' => 'tok_NEW2'));
same('success', phpwarden_RotateToken($withIds), 'rotate success');
same(array(array('UpdateClientProduct', 42, array(12 => 'tok_NEW2'))), stored(), 'new token stored');
ok(strpos(logged_text(), 'tok_NEW2') === false && strpos(logged_text(), 'tok_old') === false, 'old and new token not in log');
reset_world();
$FIELDS = array('phpwarden Project ID' => 11);
$r = phpwarden_RotateToken($withIds);
ok(is_string($r) && $r !== 'success', 'rotate refused without a token field');
same(0, count($HTTP), 'no rotate request sent');

echo "admin services tab\n";
reset_world();
$ROUTES['GET /v1/partner/projects/p_1'] = array(200, array(
    'id' => 'p_1', 'suspended' => true, 'scanned' => true, 'last_ts' => 1794500000, 'findings' => 12, 'kev' => 1,
));
$f = phpwarden_AdminServicesTabFields($withIds);
same('p_1', $f['phpwarden project'], 'project id');
same('Suspended', $f['phpwarden state'], 'state');
same(gmdate('Y-m-d H:i', 1794500000) . ' UTC', $f['Last report'], 'last report');
same('12', $f['Findings'], 'findings');
same('1', $f['Known exploited (KEV)'], 'kev');
reset_world();
$f = phpwarden_AdminServicesTabFields($withIds);
ok(is_array($f) && count($f) === 1, 'error shown as a single field');

echo "client area\n";
reset_world();
$ROUTES['POST /v1/partner/projects/p_1/embed'] = array(200, array(
    'url' => 'https://app.phpwarden.io/embed/p_1?t=SIGNEDTOKEN', 'expires' => 1794500000,
));
$r = phpwarden_ClientArea($withIds);
same('templates/clientarea', $r['templatefile'], 'template');
same(array('ttl' => 3600), $HTTP[0]['body'], 'ttl 3600');
same('https://app.phpwarden.io/embed/p_1?t=SIGNEDTOKEN', $r['vars']['embedUrl'], 'embed url passed');
same('tok_old', $r['vars']['token'], 'token passed');
same('https://app.phpwarden.io/v1/reports', $r['vars']['reportUrl'], 'report url');
ok(strpos(logged_text(), 'SIGNEDTOKEN') === false, 'embed token not in log');
ok(strpos(serialize($r), KEY) === false, 'key not in template vars');
reset_world();
$r = phpwarden_ClientArea($withIds);
same('', $r['vars']['embedUrl'], 'no url on error');
ok($r['vars']['embedError'] !== '', 'graceful error message');
reset_world();
$ROUTES['POST /v1/partner/projects/p_1/embed'] = array(200, array('url' => 'javascript:alert(1)'));
$r = phpwarden_ClientArea($withIds);
same('', $r['vars']['embedUrl'], 'non-http widget url rejected');

echo "\n$PASS passed, $FAIL failed\n";
exit($FAIL ? 1 : 0);
