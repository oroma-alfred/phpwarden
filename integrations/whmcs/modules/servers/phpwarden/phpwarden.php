<?php
/**
 * phpwarden provisioning (server) module for WHMCS.
 *
 * Creates one phpwarden project per WHMCS service through the phpwarden
 * Partner API and keeps it in step with the service lifecycle
 * (create / suspend / unsuspend / terminate).
 *
 * Partner key: read from the WHMCS server record. The "Access Hash" field
 * ($params['serveraccesshash']) is used when it is filled in; otherwise the
 * "Password" field ($params['serverpassword']) is used. Password is the
 * recommended place because WHMCS encrypts it at rest.
 *
 * Requires PHP 7.4+ with the cURL extension.
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

const PHPWARDEN_DEFAULT_BASE = 'https://app.phpwarden.io';
const PHPWARDEN_FIELD_ID = 'phpwarden Project ID';
const PHPWARDEN_FIELD_TOKEN = 'phpwarden Token';
const PHPWARDEN_TIMEOUT = 15;

/**
 * Error raised by the API layer. The message is always safe to show to an
 * admin: it never contains the partner key or a token.
 */
class PhpwardenApiException extends \Exception
{
    /** @var int HTTP status, 0 for transport failures */
    public $status = 0;
    /** @var string API error code, e.g. "not_found" */
    public $apiCode = '';

    public function __construct($message, $status = 0, $apiCode = '')
    {
        parent::__construct($message);
        $this->status = (int) $status;
        $this->apiCode = (string) $apiCode;
    }
}

// ---------------------------------------------------------------------------
// WHMCS entry points
// ---------------------------------------------------------------------------

function phpwarden_MetaData()
{
    return array(
        'DisplayName' => 'phpwarden',
        'APIVersion' => '1.1',
        'RequiresServer' => true,
    );
}

function phpwarden_ConfigOptions()
{
    return array(
        'API base URL' => array(
            'Type' => 'text',
            'Size' => '40',
            'Default' => PHPWARDEN_DEFAULT_BASE,
            'Description' => 'Optional. Leave as is unless you run your own phpwarden server.',
        ),
    );
}

function phpwarden_TestConnection(array $params)
{
    try {
        phpwarden_api($params, 'GET', '/v1/partner/projects');
        return array('success' => true, 'error' => '');
    } catch (\Throwable $e) {
        return array('success' => false, 'error' => phpwarden_error($params, $e));
    }
}

function phpwarden_CreateAccount(array $params)
{
    try {
        $serviceId = (int) $params['serviceid'];
        $name = isset($params['domain']) ? trim((string) $params['domain']) : '';
        if ($name === '') {
            $name = 'service-' . $serviceId;
        }

        $project = phpwarden_api($params, 'POST', '/v1/partner/projects', array(
            'name' => $name,
            'external_id' => phpwarden_external_id($params),
        ));
        if (empty($project['id'])) {
            throw new PhpwardenApiException('phpwarden returned no project id');
        }
        $projectId = (string) $project['id'];

        $fields = phpwarden_field_ids($params);
        $values = array();
        if (isset($fields[PHPWARDEN_FIELD_ID])) {
            $values[PHPWARDEN_FIELD_ID] = $projectId;
        }
        if (isset($fields[PHPWARDEN_FIELD_TOKEN])) {
            if (!empty($project['token'])) {
                $values[PHPWARDEN_FIELD_TOKEN] = (string) $project['token'];
            } elseif (phpwarden_field_value($params, PHPWARDEN_FIELD_TOKEN) === '') {
                // The project already existed, so the API did not repeat the
                // token and we have none stored: issue a fresh one.
                $values[PHPWARDEN_FIELD_TOKEN] = phpwarden_rotate($params, $projectId);
            }
        }
        phpwarden_store_fields($params, $fields, $values);

        return 'success';
    } catch (\Throwable $e) {
        return phpwarden_error($params, $e);
    }
}

function phpwarden_SuspendAccount(array $params)
{
    try {
        $id = phpwarden_project_id($params);
        phpwarden_api($params, 'POST', '/v1/partner/projects/' . rawurlencode($id) . '/suspend');
        return 'success';
    } catch (\Throwable $e) {
        return phpwarden_error($params, $e);
    }
}

function phpwarden_UnsuspendAccount(array $params)
{
    try {
        $id = phpwarden_project_id($params);
        phpwarden_api($params, 'POST', '/v1/partner/projects/' . rawurlencode($id) . '/unsuspend');
        return 'success';
    } catch (\Throwable $e) {
        return phpwarden_error($params, $e);
    }
}

function phpwarden_TerminateAccount(array $params)
{
    try {
        $id = phpwarden_project_id($params, false);
        if ($id !== '') {
            try {
                phpwarden_api($params, 'DELETE', '/v1/partner/projects/' . rawurlencode($id));
            } catch (PhpwardenApiException $e) {
                if ($e->status !== 404) {
                    throw $e;
                }
                // Already gone: termination is idempotent.
            }
        }
        $fields = phpwarden_field_ids($params);
        $values = array();
        foreach (array(PHPWARDEN_FIELD_ID, PHPWARDEN_FIELD_TOKEN) as $name) {
            if (isset($fields[$name])) {
                $values[$name] = '';
            }
        }
        phpwarden_store_fields($params, $fields, $values);
        return 'success';
    } catch (\Throwable $e) {
        return phpwarden_error($params, $e);
    }
}

function phpwarden_AdminCustomButtonArray()
{
    return array(
        'Rotate token' => 'RotateToken',
    );
}

function phpwarden_RotateToken(array $params)
{
    try {
        $fields = phpwarden_field_ids($params);
        if (!isset($fields[PHPWARDEN_FIELD_TOKEN])) {
            // Rotating invalidates the old token; refuse when there is
            // nowhere to keep the new one.
            throw new PhpwardenApiException(
                'Custom field "' . PHPWARDEN_FIELD_TOKEN . '" is missing on this product; token not rotated'
            );
        }
        $id = phpwarden_project_id($params);
        $token = phpwarden_rotate($params, $id);
        phpwarden_store_fields($params, $fields, array(PHPWARDEN_FIELD_TOKEN => $token));
        return 'success';
    } catch (\Throwable $e) {
        return phpwarden_error($params, $e);
    }
}

function phpwarden_AdminServicesTabFields(array $params)
{
    try {
        $id = phpwarden_project_id($params);
        $p = phpwarden_api($params, 'GET', '/v1/partner/projects/' . rawurlencode($id));

        $last = 'never';
        if (!empty($p['last_ts'])) {
            $last = is_numeric($p['last_ts'])
                ? gmdate('Y-m-d H:i', (int) $p['last_ts']) . ' UTC'
                : (string) $p['last_ts'];
        }

        return array(
            'phpwarden project' => phpwarden_h($id),
            'phpwarden state' => !empty($p['suspended']) ? 'Suspended' : 'Active',
            'Last report' => phpwarden_h($last),
            'Findings' => (string) (int) (isset($p['findings']) ? $p['findings'] : 0),
            'Known exploited (KEV)' => (string) (int) (isset($p['kev']) ? $p['kev'] : 0),
        );
    } catch (\Throwable $e) {
        return array('phpwarden' => phpwarden_h(phpwarden_error($params, $e)));
    }
}

function phpwarden_ClientArea(array $params)
{
    $base = PHPWARDEN_DEFAULT_BASE;
    $embedUrl = '';
    $error = '';
    try {
        $base = phpwarden_base_url($params);
        $id = phpwarden_project_id($params);
        $res = phpwarden_api(
            $params,
            'POST',
            '/v1/partner/projects/' . rawurlencode($id) . '/embed',
            array('ttl' => 3600)
        );
        $url = isset($res['url']) ? (string) $res['url'] : '';
        if (!preg_match('#^https?://#i', $url)) {
            throw new PhpwardenApiException('phpwarden returned no widget address');
        }
        $embedUrl = $url;
    } catch (\Throwable $e) {
        // Details go to the module log (via phpwarden_api); the customer
        // only sees a generic message.
        $error = 'The security summary is not available right now. Please try again later.';
    }

    return array(
        'templatefile' => 'templates/clientarea',
        'vars' => array(
            'embedUrl' => $embedUrl,
            'embedError' => $error,
            'token' => phpwarden_field_value($params, PHPWARDEN_FIELD_TOKEN),
            'reportUrl' => $base . '/v1/reports',
        ),
    );
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/**
 * The one place that talks to the phpwarden API.
 *
 * Returns the decoded JSON object as an array, or throws
 * PhpwardenApiException. Every call is written to the WHMCS module log with
 * the partner key and any tokens masked.
 *
 * The HTTP layer can be replaced (tests) by setting
 * $GLOBALS['phpwarden_transport'] to a callable
 * fn(string $method, string $url, array $headers, ?string $body): array
 * returning array('status' => int, 'body' => string).
 */
function phpwarden_api(array $params, $method, $path, $body = null)
{
    $key = phpwarden_key($params);
    $secrets = array($key, phpwarden_field_value($params, PHPWARDEN_FIELD_TOKEN));
    $raw = '';
    $data = null;

    try {
        if ($key === '') {
            throw new PhpwardenApiException(
                'No partner key set on the phpwarden server (Password or Access Hash field)'
            );
        }
        $url = phpwarden_base_url($params) . $path;
        $headers = array(
            'Authorization: Bearer ' . $key,
            'Accept: application/json',
        );
        $payload = null;
        if ($body !== null) {
            $payload = json_encode($body);
            $headers[] = 'Content-Type: application/json';
        }

        $transport = isset($GLOBALS['phpwarden_transport']) && is_callable($GLOBALS['phpwarden_transport'])
            ? $GLOBALS['phpwarden_transport']
            : 'phpwarden_curl';
        $res = call_user_func($transport, $method, $url, $headers, $payload);

        $status = isset($res['status']) ? (int) $res['status'] : 0;
        $raw = isset($res['body']) ? (string) $res['body'] : '';
        $data = json_decode($raw, true);

        if (is_array($data)) {
            if (!empty($data['token'])) {
                $secrets[] = (string) $data['token'];
            }
            if (!empty($data['url'])) {
                $query = parse_url((string) $data['url'], PHP_URL_QUERY);
                if (is_string($query) && $query !== '') {
                    $secrets[] = $query; // signed embed token
                }
            }
        }

        if ($status < 200 || $status >= 300) {
            $code = is_array($data) && isset($data['error']) ? (string) $data['error'] : '';
            throw new PhpwardenApiException(phpwarden_describe($status, $code), $status, $code);
        }
        if (!is_array($data)) {
            throw new PhpwardenApiException('phpwarden returned an unreadable response (HTTP ' . $status . ')', $status);
        }

        phpwarden_log($method . ' ' . $path, $body, $raw, $data, $secrets);
        return $data;
    } catch (\Throwable $e) {
        phpwarden_log($method . ' ' . $path, $body, $raw, 'ERROR: ' . $e->getMessage(), $secrets);
        throw $e;
    }
}

/** Default transport: cURL, 15 s timeout, TLS verification on. */
function phpwarden_curl($method, $url, array $headers, $body)
{
    if (!function_exists('curl_init')) {
        throw new PhpwardenApiException('The PHP cURL extension is required');
    }
    $ch = curl_init($url);
    $opts = array(
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => PHPWARDEN_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => PHPWARDEN_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_USERAGENT => 'phpwarden-whmcs/1.0',
    );
    if ($body !== null) {
        $opts[CURLOPT_POSTFIELDS] = $body;
    }
    curl_setopt_array($ch, $opts);
    $raw = curl_exec($ch);
    if ($raw === false) {
        throw new PhpwardenApiException('Could not reach phpwarden: ' . curl_error($ch));
    }
    return array(
        'status' => (int) curl_getinfo($ch, CURLINFO_HTTP_CODE),
        'body' => (string) $raw,
    );
}

function phpwarden_describe($status, $code)
{
    $known = array(
        'invalid_key' => 'phpwarden rejected the partner key (check the server record)',
        'plan_limit' => 'phpwarden plan limit reached; upgrade the plan or remove unused projects',
        'not_found' => 'phpwarden project not found',
    );
    if (isset($known[$code])) {
        return $known[$code];
    }
    return 'phpwarden API error (HTTP ' . (int) $status . ($code !== '' ? ', ' . $code : '') . ')';
}

function phpwarden_log($action, $request, $raw, $processed, array $secrets)
{
    $secrets = array_values(array_unique(array_filter($secrets, function ($s) {
        return is_string($s) && $s !== '';
    })));
    // Mask here as well as handing the values to WHMCS, so nothing secret
    // reaches the log even if replacevars handling changes.
    $mask = function ($value) use ($secrets) {
        $text = is_string($value) ? $value : json_encode($value);
        return str_replace($secrets, '***', (string) $text);
    };
    if (function_exists('logModuleCall')) {
        logModuleCall(
            'phpwarden',
            $action,
            $mask($request === null ? '' : $request),
            $mask($raw),
            $mask($processed),
            $secrets
        );
    }
}

/** Partner key from the server record: Access Hash first, then Password. */
function phpwarden_key(array $params)
{
    foreach (array('serveraccesshash', 'serverpassword') as $k) {
        if (isset($params[$k]) && trim((string) $params[$k]) !== '') {
            return trim((string) $params[$k]);
        }
    }
    return '';
}

/**
 * Base URL: the product's "API base URL" option, else the server record's
 * hostname (this is what Test Connection uses), else the default.
 */
function phpwarden_base_url(array $params)
{
    $base = isset($params['configoption1']) ? trim((string) $params['configoption1']) : '';
    if ($base === '' && !empty($params['serverhostname'])) {
        $base = trim((string) $params['serverhostname']);
    }
    if ($base === '') {
        $base = PHPWARDEN_DEFAULT_BASE;
    }
    if (strpos($base, '://') === false) {
        $base = 'https://' . $base;
    }
    $base = rtrim($base, '/');

    $scheme = strtolower((string) parse_url($base, PHP_URL_SCHEME));
    $host = strtolower((string) parse_url($base, PHP_URL_HOST));
    $local = in_array($host, array('localhost', '127.0.0.1', '[::1]'), true);
    if ($host === '' || !($scheme === 'https' || ($scheme === 'http' && $local))) {
        // Never send the partner key over plain HTTP to a remote host.
        throw new PhpwardenApiException('API base URL must be an https:// address');
    }
    return $base;
}

function phpwarden_external_id(array $params)
{
    return 'whmcs-' . (int) $params['serviceid'];
}

/** Current value of a service custom field, '' when absent. */
function phpwarden_field_value(array $params, $name)
{
    if (empty($params['customfields']) || !is_array($params['customfields'])) {
        return '';
    }
    foreach ($params['customfields'] as $field => $value) {
        if (phpwarden_field_name($field) === $name) {
            return trim((string) $value);
        }
    }
    return '';
}

/** "Name|Display name" -> "Name" */
function phpwarden_field_name($fieldname)
{
    $parts = explode('|', (string) $fieldname, 2);
    return trim($parts[0]);
}

/**
 * Project id for this service: the custom field, else a lookup by
 * external_id in the partner's project list.
 */
function phpwarden_project_id(array $params, $required = true)
{
    $id = phpwarden_field_value($params, PHPWARDEN_FIELD_ID);
    if ($id !== '') {
        return $id;
    }
    $list = phpwarden_api($params, 'GET', '/v1/partner/projects');
    $want = phpwarden_external_id($params);
    if (isset($list['projects']) && is_array($list['projects'])) {
        foreach ($list['projects'] as $p) {
            if (is_array($p) && isset($p['external_id'], $p['id']) && (string) $p['external_id'] === $want) {
                return (string) $p['id'];
            }
        }
    }
    if ($required) {
        throw new PhpwardenApiException('No phpwarden project exists for this service; run Create first');
    }
    return '';
}

function phpwarden_rotate(array $params, $projectId)
{
    $res = phpwarden_api($params, 'POST', '/v1/partner/projects/' . rawurlencode($projectId) . '/token');
    if (empty($res['token'])) {
        throw new PhpwardenApiException('phpwarden returned no token');
    }
    return (string) $res['token'];
}

/**
 * Map of our custom field names to their WHMCS field ids for this product.
 * Only fields that exist on the product are returned.
 *
 * Tests may set $GLOBALS['phpwarden_field_lookup'] to a callable
 * fn(int $productId): array<string name, int id>.
 */
function phpwarden_field_ids(array $params)
{
    $pid = 0;
    foreach (array('pid', 'packageid') as $k) {
        if (!empty($params[$k])) {
            $pid = (int) $params[$k];
            break;
        }
    }

    $rows = array();
    if (isset($GLOBALS['phpwarden_field_lookup']) && is_callable($GLOBALS['phpwarden_field_lookup'])) {
        $rows = call_user_func($GLOBALS['phpwarden_field_lookup'], $pid);
    } elseif ($pid > 0 && class_exists('\\WHMCS\\Database\\Capsule')) {
        $found = \WHMCS\Database\Capsule::table('tblcustomfields')
            ->where('type', 'product')
            ->where('relid', $pid)
            ->get(array('id', 'fieldname'));
        foreach ($found as $row) {
            $rows[phpwarden_field_name($row->fieldname)] = (int) $row->id;
        }
    }

    $out = array();
    foreach (array(PHPWARDEN_FIELD_ID, PHPWARDEN_FIELD_TOKEN) as $name) {
        if (!empty($rows[$name])) {
            $out[$name] = (int) $rows[$name];
        }
    }
    return $out;
}

/** Write custom field values through the UpdateClientProduct API. */
function phpwarden_store_fields(array $params, array $fieldIds, array $values)
{
    $byId = array();
    foreach ($values as $name => $value) {
        if (isset($fieldIds[$name])) {
            $byId[$fieldIds[$name]] = (string) $value;
        }
    }
    if (!$byId) {
        return;
    }
    $result = localAPI('UpdateClientProduct', array(
        'serviceid' => (int) $params['serviceid'],
        'customfields' => base64_encode(serialize($byId)),
    ));
    if (!is_array($result) || !isset($result['result']) || $result['result'] !== 'success') {
        throw new PhpwardenApiException('Could not save the phpwarden custom fields in WHMCS');
    }
}

/** Short, key-free error string for WHMCS. */
function phpwarden_error(array $params, \Throwable $e)
{
    $msg = $e instanceof PhpwardenApiException ? $e->getMessage() : 'phpwarden module error: ' . $e->getMessage();
    $key = phpwarden_key($params);
    if ($key !== '') {
        $msg = str_replace($key, '***', $msg);
    }
    return $msg;
}

function phpwarden_h($s)
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}
