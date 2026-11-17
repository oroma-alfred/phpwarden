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
$ok( 'no commands class', ! file_exists( $dir . '/includes/class-phpwarden-commands.php' ) && false === strpos( $code, 'PHPWarden_Commands' ) );
foreach ( array( 'Plugin_Upgrader', 'Theme_Upgrader', 'deactivate_plugins', 'activate_plugin', 'wp_create_user', 'wp_insert_user', 'set_role', "'commands'" ) as $needle ) {
	$ok( "never uses $needle", false === strpos( $code, $needle ) );
}
$ok( 'only one outbound endpoint (/v1/inventory)', 1 === preg_match_all( "#'/v1/#", $code ) );
$ok( 'payload says remote_updates false', false !== strpos( $code, "'remote_updates' => false" ) );
echo $fail ? "RESULT: $fail FAILED\n" : "RESULT: ALL PASS\n";
exit( $fail ? 1 : 0 );
