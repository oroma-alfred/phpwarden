<?php
/**
 * Uninstall: remove options and cron events.
 *
 * @package PHPWarden
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) || ! defined( 'ABSPATH' ) ) {
	exit;
}

$phpwarden_switched = false;
if ( is_multisite() && ! is_main_site() ) {
	switch_to_blog( get_main_site_id() );
	$phpwarden_switched = true;
}

foreach ( array( 'phpwarden_token', 'phpwarden_api_base', 'phpwarden_remote_updates', 'phpwarden_status', 'phpwarden_log' ) as $phpwarden_option ) {
	delete_option( $phpwarden_option );
}
delete_transient( 'phpwarden_sync_lock' );
wp_clear_scheduled_hook( 'phpwarden_sync' );
wp_clear_scheduled_hook( 'phpwarden_sync_soon' );

if ( $phpwarden_switched ) {
	restore_current_blog();
}
