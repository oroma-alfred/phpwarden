<?php
/**
 * Dependency-free tests for the phpwarden WordPress plugin.
 *
 * Run: php integrations/wordpress-plugin/tests/run-tests.php
 *
 * Stubs the few WordPress functions the testable classes use. The second
 * mode (`constants`) is run in a child process to check wp-config.php
 * constant precedence, since constants cannot be undefined.
 */

define( 'ABSPATH', __DIR__ . '/' );
define( 'PHPWARDEN_VERSION', '1.0.0' );

$GLOBALS['t_options']    = array();
$GLOBALS['t_plugins']    = array();
$GLOBALS['t_themes']     = array();
$GLOBALS['t_transients'] = array();
$GLOBALS['t_active']     = array();

function get_option( $name, $default = false ) {
	return array_key_exists( $name, $GLOBALS['t_options'] ) ? $GLOBALS['t_options'][ $name ] : $default;
}
function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['t_options'][ $name ] = $value;
	return true;
}
function delete_option( $name ) {
	unset( $GLOBALS['t_options'][ $name ] );
	return true;
}
function apply_filters( $hook, $value ) {
	return $value;
}
function wp_parse_url( $url ) {
	return parse_url( $url );
}
function wp_strip_all_tags( $text ) {
	return trim( strip_tags( $text ) );
}
function wp_json_encode( $data ) {
	return json_encode( $data );
}
function get_plugins() {
	return $GLOBALS['t_plugins'];
}
function wp_get_themes() {
	return $GLOBALS['t_themes'];
}
function get_site_transient( $name ) {
	return isset( $GLOBALS['t_transients'][ $name ] ) ? $GLOBALS['t_transients'][ $name ] : false;
}
function is_plugin_active( $file ) {
	return in_array( $file, $GLOBALS['t_active'], true );
}
function is_plugin_active_for_network( $file ) {
	return false;
}
function is_multisite() {
	return false;
}
function home_url() {
	return 'https://example.com';
}
function get_stylesheet() {
	return 'child';
}
function get_template() {
	return 'twentytwentyfour';
}
function wp_get_wp_version() {
	return '6.5.2';
}

class T_Theme {
	private $data;
	public function __construct( $name, $version ) {
		$this->data = array( 'Name' => $name, 'Version' => $version );
	}
	public function get( $key ) {
		return isset( $this->data[ $key ] ) ? $this->data[ $key ] : '';
	}
}

$base = dirname( __DIR__ ) . '/phpwarden/includes/';
require $base . 'class-phpwarden-settings.php';
require $base . 'class-phpwarden-inventory.php';
require $base . 'class-phpwarden-commands.php';

$GLOBALS['t_pass'] = 0;
$GLOBALS['t_fail'] = 0;
function check( $label, $cond ) {
	if ( $cond ) {
		++$GLOBALS['t_pass'];
		echo "ok   - $label\n";
	} else {
		++$GLOBALS['t_fail'];
		echo "FAIL - $label\n";
	}
}
function same( $label, $expected, $actual ) {
	$ok = $expected === $actual;
	check( $label, $ok );
	if ( ! $ok ) {
		echo '       expected: ' . var_export( $expected, true ) . "\n       actual:   " . var_export( $actual, true ) . "\n";
	}
}
function finish() {
	echo "\n{$GLOBALS['t_pass']} passed, {$GLOBALS['t_fail']} failed\n";
	exit( $GLOBALS['t_fail'] ? 1 : 0 );
}

/* ---------- child mode: wp-config.php constants ---------- */
if ( isset( $argv[1] ) && 'constants' === $argv[1] ) {
	define( 'PHPWARDEN_TOKEN', 'const-token-ABCD' );
	define( 'PHPWARDEN_REMOTE_UPDATES', false );
	define( 'PHPWARDEN_API', 'https://staging.example.test/' );
	update_option( 'phpwarden_token', 'option-token-WXYZ' );
	update_option( 'phpwarden_remote_updates', '1' );
	update_option( 'phpwarden_api_base', 'https://other.example.com' );

	check( 'constant: token is read-only', PHPWarden_Settings::token_is_constant() );
	same( 'constant: token wins over option', 'const-token-ABCD', PHPWarden_Settings::get_token() );
	check( 'constant: remote updates is read-only', PHPWarden_Settings::remote_is_constant() );
	same( 'constant: PHPWARDEN_REMOTE_UPDATES=false wins over enabled option', false, PHPWarden_Settings::remote_updates_enabled() );
	same( 'constant: API base wins over option', 'https://staging.example.test', PHPWarden_Settings::get_api_base() );
	$v = PHPWarden_Commands::validate(
		array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'akismet', 'file' => 'akismet/akismet.php' ),
		PHPWarden_Settings::remote_updates_enabled(),
		array( 'akismet/akismet.php' ),
		array()
	);
	same( 'constant: command rejected when constant disables remote updates', 'remote_updates_disabled', $v['reason'] );
	finish();
}

/* ---------- fixtures ---------- */
$GLOBALS['t_plugins'] = array(
	'akismet/akismet.php'      => array( 'Name' => 'Akismet', 'Version' => '5.3' ),
	'hello.php'                => array( 'Name' => 'Hello Dolly', 'Version' => '1.7.2' ),
	'woo/woocommerce.php'      => array( 'Name' => '<b>Woo</b>', 'Version' => '8.0.0' ),
	'multi/one.php'            => array( 'Name' => 'Multi One', 'Version' => '1.0' ),
	'multi/two.php'            => array( 'Name' => 'Multi Two', 'Version' => '1.0' ),
	'phpwarden/phpwarden.php'  => array( 'Name' => 'phpwarden agent', 'Version' => '1.0.0' ),
);
$GLOBALS['t_active']  = array( 'akismet/akismet.php', 'phpwarden/phpwarden.php' );
$GLOBALS['t_themes']  = array(
	'twentytwentyfour' => new T_Theme( 'Twenty Twenty-Four', '1.0' ),
	'child'            => new T_Theme( 'Child', '0.1' ),
	'old'              => new T_Theme( 'Old', '2.0' ),
);
$up_plugins           = new stdClass();
$up_plugins->response = array(
	'akismet/akismet.php' => (object) array( 'new_version' => '5.3.1', 'package' => 'https://downloads.wordpress.org/x.zip' ),
	'woo/woocommerce.php' => (object) array( 'new_version' => '8.0.0' ), // Not newer.
);
$up_themes            = new stdClass();
$up_themes->response  = array( 'old' => array( 'new_version' => '2.1' ) );
$GLOBALS['t_transients'] = array( 'update_plugins' => $up_plugins, 'update_themes' => $up_themes );

/* ---------- slug derivation ---------- */
same( 'slug: directory name', 'akismet', PHPWarden_Inventory::plugin_slug( 'akismet/akismet.php' ) );
same( 'slug: directory differs from file', 'woo', PHPWarden_Inventory::plugin_slug( 'woo/woocommerce.php' ) );
same( 'slug: single-file plugin uses file stem', 'hello', PHPWarden_Inventory::plugin_slug( 'hello.php' ) );
same( 'slug: single-file stem keeps inner dots', 'my.plugin', PHPWarden_Inventory::plugin_slug( 'my.plugin.php' ) );

/* ---------- inventory shape ---------- */
$inv = PHPWarden_Inventory::collect( false );
same( 'inventory: top-level keys match contract', array( 'agent', 'site_url', 'php', 'wordpress', 'remote_updates' ), array_keys( $inv ) );
same( 'inventory: agent', 'phpwarden-wp/1.0.0', $inv['agent'] );
same( 'inventory: site_url', 'https://example.com', $inv['site_url'] );
same( 'inventory: php keys', array( 'version', 'sapi' ), array_keys( $inv['php'] ) );
same( 'inventory: php version', PHP_VERSION, $inv['php']['version'] );
same( 'inventory: php sapi', php_sapi_name(), $inv['php']['sapi'] );
same( 'inventory: wordpress keys', array( 'core', 'plugins', 'themes' ), array_keys( $inv['wordpress'] ) );
same( 'inventory: core', '6.5.2', $inv['wordpress']['core'] );
same( 'inventory: remote_updates false is a boolean', false, $inv['remote_updates'] );
same( 'inventory: remote_updates true', true, PHPWarden_Inventory::collect( true )['remote_updates'] );

$p = $inv['wordpress']['plugins'];
same( 'plugins: is a list', range( 0, 5 ), array_keys( $p ) );
same(
	'plugins: row matches contract example',
	array( 'slug' => 'akismet', 'file' => 'akismet/akismet.php', 'name' => 'Akismet', 'version' => '5.3', 'active' => true, 'update' => '5.3.1' ),
	$p[0]
);
same(
	'plugins: single-file row, inactive, update null',
	array( 'slug' => 'hello', 'file' => 'hello.php', 'name' => 'Hello Dolly', 'version' => '1.7.2', 'active' => false, 'update' => null ),
	$p[1]
);
same( 'plugins: same-version transient entry is not an update', null, $p[2]['update'] );
same( 'plugins: name has tags stripped', 'Woo', $p[2]['name'] );

$t = $inv['wordpress']['themes'];
same(
	'themes: row matches contract (no file key), parent of active child is active',
	array( 'slug' => 'twentytwentyfour', 'name' => 'Twenty Twenty-Four', 'version' => '1.0', 'active' => true, 'update' => null ),
	$t[0]
);
same( 'themes: active stylesheet', true, $t[1]['active'] );
same( 'themes: inactive with update from array transient', array( false, '2.1' ), array( $t[2]['active'], $t[2]['update'] ) );

same( 'update: missing transient gives null', null, PHPWarden_Inventory::update_version( false, 'akismet/akismet.php', '5.3' ) );

$json = PHPWarden_Inventory::encode( $inv );
check( 'encode: valid JSON under size cap', is_string( $json ) && strlen( $json ) < PHPWarden_Inventory::MAX_BYTES && json_decode( $json, true ) === $inv );
check( 'encode: size cap is well under the 512 KB server limit', PHPWarden_Inventory::MAX_BYTES < 512 * 1024 * 0.8 );
check( 'encode: package URL from the transient is not sent', false === strpos( $json, 'downloads.wordpress.org' ) );
$big = $inv;
for ( $i = 0; $i < 3000; $i++ ) {
	$big['wordpress']['plugins'][] = array( 'slug' => "p$i", 'file' => "p$i/p$i.php", 'name' => str_repeat( 'n', 200 ), 'version' => '1.0', 'active' => false, 'update' => null );
}
$big_json = PHPWarden_Inventory::encode( $big );
check( 'encode: oversized payload drops names to fit', is_string( $big_json ) && strlen( $big_json ) <= PHPWarden_Inventory::MAX_BYTES );
for ( $i = 0; $i < 20000; $i++ ) {
	$big['wordpress']['plugins'][] = array( 'slug' => "q$i", 'file' => "q$i/q$i.php", 'name' => 'x', 'version' => '1.0', 'active' => false, 'update' => null );
}
same( 'encode: refuses when it cannot fit', false, PHPWarden_Inventory::encode( $big ) );

/* ---------- command validation ---------- */
$files  = array_keys( get_plugins() );
$themes = array_keys( wp_get_themes() );
$self   = 'phpwarden/phpwarden.php';
$val    = function ( $cmd, $enabled = true ) use ( $files, $themes, $self ) {
	return PHPWarden_Commands::validate( $cmd, $enabled, $files, $themes, $self );
};
$good   = array( 'id' => 'c_ab12', 'action' => 'update_plugin', 'slug' => 'akismet', 'file' => 'akismet/akismet.php' );

$v = $val( $good );
same( 'validate: contract example accepted', array( true, 'akismet/akismet.php' ), array( $v['valid'], $v['target'] ) );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_theme', 'slug' => 'old' ) );
same( 'validate: update_theme accepted (slug only)', array( true, 'old' ), array( $v['valid'], $v['target'] ) );
$v = $val( array( 'id' => 'c_1', 'action' => 'deactivate_plugin', 'slug' => 'hello', 'file' => 'hello.php' ) );
same( 'validate: deactivate_plugin accepted for single-file plugin', array( true, 'hello.php' ), array( $v['valid'], $v['target'] ) );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'woo' ) );
same( 'validate: plugin resolved by slug when file omitted', array( true, 'woo/woocommerce.php' ), array( $v['valid'], $v['target'] ) );

foreach ( array( 'install_plugin', 'delete_plugin', 'activate_plugin', 'update_core', 'UPDATE_PLUGIN', 'update_plugin ', '', 'exec' ) as $action ) {
	$v = $val( array_merge( $good, array( 'action' => $action ) ) );
	same( "validate: unknown action rejected ('$action')", array( false, 'unknown_action' ), array( $v['valid'], $v['reason'] ) );
}
$v = $val( array( 'id' => 'c_1', 'slug' => 'akismet' ) );
same( 'validate: missing action rejected', 'unknown_action', $v['reason'] );
$v = $val( array_merge( $good, array( 'action' => array( 'update_plugin' ) ) ) );
same( 'validate: non-string action rejected', 'unknown_action', $v['reason'] );

$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'nope', 'file' => 'nope/nope.php' ) );
same( 'validate: unknown plugin file rejected', array( false, 'unknown_file' ), array( $v['valid'], $v['reason'] ) );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'nope' ) );
same( 'validate: unknown plugin slug rejected', array( false, 'unknown_slug' ), array( $v['valid'], $v['reason'] ) );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_theme', 'slug' => 'nope' ) );
same( 'validate: unknown theme slug rejected', array( false, 'unknown_slug' ), array( $v['valid'], $v['reason'] ) );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_theme', 'slug' => 'akismet' ) );
same( 'validate: plugin slug is not a theme', false, $v['valid'] );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'akismet', 'file' => 'hello.php' ) );
same( 'validate: slug/file mismatch rejected', array( false, 'slug_file_mismatch' ), array( $v['valid'], $v['reason'] ) );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'multi' ) );
same( 'validate: ambiguous slug without file rejected', array( false, 'ambiguous_slug' ), array( $v['valid'], $v['reason'] ) );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'multi', 'file' => 'multi/two.php' ) );
same( 'validate: ambiguous slug with exact file accepted', 'multi/two.php', $v['target'] );
foreach ( array( '../../wp-config.php', '/etc/passwd', 'akismet/../hello.php', 'https://evil.example/x.zip', 'AKISMET/akismet.php', 'akismet/akismet.php ' ) as $path ) {
	$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'akismet', 'file' => $path ) );
	same( "validate: path not in get_plugins() rejected ('$path')", false, $v['valid'] );
}
foreach ( array( '../old', 'https://evil.example/t.zip', 'Old', '' ) as $slug ) {
	$v = $val( array( 'id' => 'c_1', 'action' => 'update_theme', 'slug' => $slug ) );
	same( "validate: theme slug not installed rejected ('$slug')", false, $v['valid'] );
}
$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'akismet', 'file' => array( 'akismet/akismet.php' ) ) );
same( 'validate: non-string file rejected', false, $v['valid'] );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_theme', 'slug' => 0 ) );
same( 'validate: non-string slug rejected', false, $v['valid'] );
$v = $val( array_merge( $good, array( 'url' => 'https://evil.example/x.zip', 'package' => 'https://evil.example/x.zip' ) ) );
same( 'validate: extra server fields (url/package) are dropped', array( 'valid', 'reason', 'id', 'action', 'slug', 'target' ), array_keys( $v ) );

foreach ( array( '../c', 'c/1', 'c 1', '', str_repeat( 'a', 65 ), 12 ) as $id ) {
	$v = $val( array_merge( $good, array( 'id' => $id ) ) );
	same( 'validate: bad id rejected (' . var_export( $id, true ) . ')', array( false, 'bad_id' ), array( $v['valid'], $v['reason'] ) );
}
$v = $val( 'update_plugin' );
same( 'validate: non-array command rejected', 'malformed', $v['reason'] );
$v = $val( array( 'id' => 'c_1', 'action' => 'deactivate_plugin', 'slug' => 'phpwarden', 'file' => $self ) );
same( 'validate: agent cannot be told to deactivate itself', 'cannot_deactivate_agent', $v['reason'] );
$v = $val( array( 'id' => 'c_1', 'action' => 'update_plugin', 'slug' => 'phpwarden', 'file' => $self ) );
same( 'validate: agent can be updated', true, $v['valid'] );

// Remote updates off: everything is rejected.
foreach ( array( $good, array( 'id' => 'c_1', 'action' => 'update_theme', 'slug' => 'old' ), array( 'id' => 'c_1', 'action' => 'deactivate_plugin', 'slug' => 'hello' ) ) as $cmd ) {
	$v = $val( $cmd, false );
	same( "validate: {$cmd['action']} rejected when remote updates are off", array( false, 'remote_updates_disabled' ), array( $v['valid'], $v['reason'] ) );
}
foreach ( array( 1, 'yes', '1', null ) as $truthy ) {
	$v = $val( $good, $truthy );
	same( 'validate: only boolean true enables (' . var_export( $truthy, true ) . ')', false, $v['valid'] );
}
same( 'select: no commands when remote updates are off', array(), PHPWarden_Commands::select( array( $good, $good ), false ) );
same( 'select: at most 5 commands per sync', 5, count( PHPWarden_Commands::select( array_fill( 0, 9, $good ), true ) ) );
same( 'select: non-array commands ignored', array(), PHPWarden_Commands::select( 'x', true ) );
same( 'actions: exactly the three contract actions', array( 'update_plugin', 'update_theme', 'deactivate_plugin' ), PHPWarden_Commands::allowed_actions() );

$r = PHPWarden_Commands::result( true, '5.3', '5.3.1', '' );
same( 'result: shape matches contract', array( 'ok' => true, 'from' => '5.3', 'to' => '5.3.1', 'message' => '' ), $r );

/* ---------- settings ---------- */
same( 'mask: shows only last 4', '********1234', PHPWarden_Settings::mask_token( 'pw_live_abcdefgh1234' ) );
check( 'mask: does not leak the rest', false === strpos( PHPWarden_Settings::mask_token( 'pw_live_abcdefgh1234' ), 'abcdefgh' ) );
same( 'mask: mask length does not reveal token length', strlen( PHPWarden_Settings::mask_token( str_repeat( 'a', 60 ) ) ), strlen( PHPWarden_Settings::mask_token( str_repeat( 'a', 12 ) ) ) );
same( 'mask: short token fully masked', '********', PHPWarden_Settings::mask_token( 'abc1234' ) );
same( 'mask: empty token', '', PHPWarden_Settings::mask_token( '' ) );
same( 'token: sanitised', 'abc-DEF_123', PHPWarden_Settings::sanitize_token( "  abc-DEF_123\r\n" ) );
same( 'token: header injection characters removed', 'abcX-Evil:1', PHPWarden_Settings::sanitize_token( "abc\r\nX-Evil: 1" ) );
same( 'token: default empty', '', PHPWarden_Settings::get_token() );
PHPWarden_Settings::set_token( 'tok_abcdefgh9876' );
same( 'token: stored and read back', 'tok_abcdefgh9876', PHPWarden_Settings::get_token() );

same( 'remote: off by default', false, PHPWarden_Settings::remote_updates_enabled() );
PHPWarden_Settings::set_remote_updates( true );
same( 'remote: on after opt-in', true, PHPWarden_Settings::remote_updates_enabled() );
PHPWarden_Settings::set_remote_updates( false );
same( 'remote: off again', false, PHPWarden_Settings::remote_updates_enabled() );

same( 'api: default', 'https://app.phpwarden.io', PHPWarden_Settings::get_api_base() );
same( 'api: trailing slash removed', 'https://eu.example.com/api', PHPWarden_Settings::sanitize_api_base( 'https://eu.example.com/api/' ) );
same( 'api: plain http rejected', '', PHPWarden_Settings::sanitize_api_base( 'http://app.phpwarden.io' ) );
same( 'api: http allowed for localhost', 'http://localhost:8080', PHPWarden_Settings::sanitize_api_base( 'http://localhost:8080' ) );
same( 'api: credentials rejected', '', PHPWarden_Settings::sanitize_api_base( 'https://user:pass@example.com' ) );
same( 'api: query rejected', '', PHPWarden_Settings::sanitize_api_base( 'https://example.com/?x=1' ) );
same( 'api: other schemes rejected', '', PHPWarden_Settings::sanitize_api_base( 'file:///etc/passwd' ) );
PHPWarden_Settings::set_api_base( 'javascript:alert(1)' );
same( 'api: invalid value falls back to default', 'https://app.phpwarden.io', PHPWarden_Settings::get_api_base() );

for ( $i = 1; $i <= 60; $i++ ) {
	PHPWarden_Settings::add_log( array( 'time' => $i, 'action' => 'update_plugin', 'slug' => 'akismet', 'ok' => true ) );
}
$log = PHPWarden_Settings::get_log();
same( 'log: capped at 50 entries, newest first', array( 50, 60, 11 ), array( count( $log ), $log[0]['time'], $log[49]['time'] ) );

/* ---------- constants (child process) ---------- */
$out = array();
$rc  = 1;
exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( __FILE__ ) . ' constants', $out, $rc );
foreach ( $out as $line ) {
	if ( 0 === strpos( $line, 'ok ' ) || 0 === strpos( $line, 'FAIL' ) ) {
		echo $line . "\n";
	}
}
check( 'constants: child process passed', 0 === $rc );

finish();
