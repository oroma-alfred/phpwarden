<?php
/**
 * Usage names (reachability) in the WordPress.org edition: consent-gated, names only.
 * Run: php integrations/wordpress-plugin/tests/run-tests-usage.php
 */
define( 'ABSPATH', '/tmp/' );
define( 'WPINC', 'wp-includes' );
define( 'PHPWARDEN_VERSION', 'test' );
$fail = 0;
$ok   = function ( $name, $cond ) use ( &$fail ) {
	echo ( $cond ? 'PASS ' : 'FAIL ' ) . $name . "\n";
	$fail += $cond ? 0 : 1;
};
$GLOBALS['opts'] = array();
function get_option( $k, $d = false ) { return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['opts'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['opts'][ $k ] ); return true; }
function apply_filters( $h, $v ) { return $v; }
function wp_json_encode( $d ) { return json_encode( $d ); }
function wp_strip_all_tags( $t ) { return trim( strip_tags( $t ) ); }
function get_plugins() { return array(); }
function wp_get_themes() { return array(); }
function get_stylesheet() { return 'tt4'; }
function get_template() { return 'tt4'; }
function home_url() { return 'https://example.test'; }
function get_site_transient( $n ) { return false; }
function wp_installing() { return true; }
function has_action() { return false; }
function wp_get_wp_version() { return '6.7'; }
function is_multisite() { return false; }
class T_Wpdb {
	public $posts   = 'wp_posts';
	public $queries = array();
	public function prepare( $q, ...$a ) { return vsprintf( str_replace( '%d', '%d', $q ), $a ); }
	public function get_col( $q ) {
		$this->queries[] = $q;
		return false !== strpos( $q, 'OFFSET 0' ) ? array( '<p>[contact-form-7 id="1"] [notregistered]</p>', '<!-- wp:contact-form-7/contact-form-selector {"id":1} /-->' ) : array();
	}
}
$GLOBALS['wpdb']           = new T_Wpdb();
$GLOBALS['shortcode_tags'] = array( 'contact-form-7' => 'f', 'gallery' => 'g' );
$GLOBALS['wp_filter']      = array( 'init' => 1, 'wp_ajax_nopriv_xoo_do' => 1, 'wp_ajax_save_thing' => 1 );

$dir = dirname( __DIR__ ) . '/phpwarden/includes/';
require $dir . 'class-phpwarden-settings.php';
require $dir . 'class-phpwarden-inventory.php';

// ---- consent gating ----
$p = PHPWarden_Inventory::collect();
$ok( 'no consent: no usage field', ! isset( $p['usage'] ) );
PHPWarden_Settings::set_usage_consent( true );
$ok( 'usage box alone (no main consent): not granted', ! PHPWarden_Settings::has_usage_consent() );
$ok( 'usage box alone: no usage field', ! isset( PHPWarden_Inventory::collect()['usage'] ) );
PHPWarden_Settings::set_consent( true );
PHPWarden_Settings::set_usage_consent( false );
$ok( 'main consent only: no usage field', ! isset( PHPWarden_Inventory::collect()['usage'] ) );
$ok( 'main consent only: no posts read', array() === $GLOBALS['wpdb']->queries );
PHPWarden_Settings::set_usage_consent( true );
$p = PHPWarden_Inventory::collect();
$ok( 'both consents: usage field present', isset( $p['usage'] ) );
$u = $p['usage'];
$ok( 'shortcodes: only registered names seen in content', array( 'contact-form-7' ) === $u['shortcodes_used'] );
$ok( 'ajax: action names without prefix', array( 'save_thing', 'xoo_do' ) === $u['ajax_actions'] );
$ok( 'posts counted', 2 === $u['posts'] );
$ok( 'only SELECT queries', 0 === count( array_filter( $GLOBALS['wpdb']->queries, function ( $q ) { return 0 !== strpos( $q, 'SELECT' ); } ) ) );
$json = wp_json_encode( $p );
$ok( 'no content in the payload', false === strpos( $json, '<p>' ) && false === strpos( $json, 'notregistered' ) && false === strpos( $json, 'id=' ) );
$ok( 'remote_updates still false', false === $p['remote_updates'] );
$ok( 'usage option removed on uninstall', in_array( 'phpwarden_usage_consent', PHPWarden_Settings::option_names(), true ) );

// ---- pure builder ----
$b = PHPWarden_Inventory::build_usage(
	array( '<!-- wp:acme/form /-->', '{"content":"<!-- wp:acme\/slider -->"}' ),
	array(),
	array( 'acme/form', 'acme/slider', 'acme/unused' ),
	array( 'wp/v2', 'bad name!' ),
	array()
);
$ok( 'blocks: registered and used (incl. JSON-escaped widget)', array( 'acme/form', 'acme/slider' ) === $b['blocks_used'] );
$ok( 'rest: invalid names dropped', array( 'wp/v2' ) === $b['rest_namespaces'] );
$many = PHPWarden_Inventory::build_usage( array(), array(), array(), array_map( function ( $i ) { return "ns$i/v1"; }, range( 1, 500 ) ), array() );
$ok( 'lists capped at 300 names', 300 === count( $many['rest_namespaces'] ) );

$admin = file_get_contents( $dir . 'class-phpwarden-admin.php' );
$ok( 'usage checkbox unchecked by default', false !== strpos( $admin, 'checked( PHPWarden_Settings::has_usage_consent() )' ) );
$ok( 'usage consent saved only with main consent', false !== strpos( $admin, "! empty( \$_POST['phpwarden_consent'] ) && ! empty( \$_POST['phpwarden_usage_consent'] )" ) );
echo $fail ? "RESULT: $fail FAILED\n" : "RESULT: ALL PASS\n";
exit( $fail ? 1 : 0 );
