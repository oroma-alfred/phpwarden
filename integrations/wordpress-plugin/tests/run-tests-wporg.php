<?php
/**
 * Checks that the WordPress.org edition is report-only.
 * Run: php integrations/wordpress-plugin/tests/run-tests-wporg.php
 */
$dir  = dirname( __DIR__ ) . '/phpwarden';
$fail = 0;
$ok   = function ( $name, $cond ) use ( &$fail ) {
	echo ( $cond ? 'PASS ' : 'FAIL ' ) . $name . "\n";
	$fail += $cond ? 0 : 1;
};
$code = '';
foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir ) ) as $f ) {
	if ( substr( $f, -4 ) === '.php' ) {
		$code .= file_get_contents( $f );
	}
}
foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir ) ) as $f ) {
	if ( substr( $f, -4 ) === '.php' ) {
		exec( escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( (string) $f ) . ' 2>&1', $out, $rc );
		$ok( 'syntax ' . basename( $f ), 0 === $rc );
	}
}
$ok( 'no commands class', ! file_exists( $dir . '/includes/class-phpwarden-commands.php' ) && false === strpos( $code, 'PHPWarden_Commands' ) );
foreach ( array( 'Plugin_Upgrader', 'Theme_Upgrader', 'deactivate_plugins', 'activate_plugin', 'wp_create_user', 'wp_insert_user', 'set_role', "'commands'" ) as $needle ) {
	$ok( "never uses $needle", false === strpos( $code, $needle ) );
}
$ok( 'only one outbound endpoint (/v1/inventory)', 1 === preg_match_all( "#'/v1/#", $code ) );
$ok( 'payload says remote_updates false', false !== strpos( $code, "'remote_updates' => false" ) );

// ---- behaviour: nothing is sent or scheduled without consent ----
define( 'ABSPATH', '/tmp/' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'PHPWARDEN_VERSION', 'test' );
$GLOBALS['opts'] = array(); $GLOBALS['posts'] = 0; $GLOBALS['sched'] = array(); $GLOBALS['tr'] = array();
function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['opts'][ $k ] ); return true; }
function get_transient( $k ) { return isset( $GLOBALS['tr'][ $k ] ) ? $GLOBALS['tr'][ $k ] : false; }
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['tr'][ $k ] = $v; }
function delete_transient( $k ) { unset( $GLOBALS['tr'][ $k ] ); }
function __( $s, $d = null ) { return $s; }
function sanitize_key( $s ) { return strtolower( preg_replace( "/[^a-z0-9_\-]/i", "", $s ) ); }
function sanitize_text_field( $s ) { return trim( strip_tags( (string) $s ) ); }
function json_decode_safe() {}
function apply_filters( $h, $v ) { return $v; }
function wp_parse_url( $u ) { return parse_url( $u ); }
function is_multisite() { return false; }
function is_main_site() { return true; }
function wp_next_scheduled( $h ) { return isset( $GLOBALS['sched'][ $h ] ) ? 1 : false; }
function wp_schedule_event( $t, $r, $h ) { $GLOBALS['sched'][ $h ] = 1; }
function wp_schedule_single_event( $t, $h ) { $GLOBALS['sched'][ $h ] = 1; }
function wp_clear_scheduled_hook( $h ) { unset( $GLOBALS['sched'][ $h ] ); }
function add_action() {}
function wp_remote_post( $u, $a ) { $GLOBALS['posts']++; return array( 'code' => 200, 'body' => '{"stored":1,"exposed":0,"kev":0}' ); }
function is_wp_error( $x ) { return false; }
function wp_remote_retrieve_response_code( $r ) { return $r['code']; }
function wp_remote_retrieve_body( $r ) { return $r['body']; }
class PHPWarden_Inventory { static function collect() { return array( 'x' => 1 ); } static function encode( $a ) { return json_encode( $a ); } }
require $dir . '/includes/class-phpwarden-settings.php';
require $dir . '/includes/class-phpwarden-client.php';
require $dir . '/includes/class-phpwarden-plugin.php';

PHPWarden_Settings::set_token( 'tok_abcdefgh1234' );
$st = PHPWarden_Client::sync( 'cron' );
$ok( 'token alone: sync sends nothing', 0 === $GLOBALS['posts'] && empty( $st['ok'] ) );
PHPWarden_Plugin::ensure_schedule();
$ok( 'token alone: no cron scheduled', empty( $GLOBALS['sched'] ) );
PHPWarden_Plugin::schedule_soon();
$ok( 'token alone: no change report scheduled', empty( $GLOBALS['sched'] ) );
PHPWarden_Settings::set_consent( true );
PHPWarden_Plugin::ensure_schedule();
$ok( 'consent: cron scheduled', ! empty( $GLOBALS['sched'][ PHPWarden_Plugin::CRON_HOOK ] ) );
PHPWarden_Client::sync( 'manual' );
$ok( 'consent + token: one report sent', 1 === $GLOBALS['posts'] );
PHPWarden_Settings::set_consent( false );
PHPWarden_Plugin::ensure_schedule();
PHPWarden_Client::sync( 'cron' );
$ok( 'consent withdrawn: cron cleared and nothing sent', empty( $GLOBALS['sched'][ PHPWarden_Plugin::CRON_HOOK ] ) && 1 === $GLOBALS['posts'] );
$ok( 'consent option removed on uninstall', in_array( 'phpwarden_consent', PHPWarden_Settings::option_names(), true ) );
$ok( 'admin checkbox unchecked by default', false !== strpos( $code, "checked( PHPWarden_Settings::has_consent() )" ) );
$ok( 'CLI activate requires --consent', false !== strpos( $code, "empty( \$assoc_args['consent'] )" ) );
echo $fail ? "RESULT: $fail FAILED\n" : "RESULT: ALL PASS\n";
exit( $fail ? 1 : 0 );
