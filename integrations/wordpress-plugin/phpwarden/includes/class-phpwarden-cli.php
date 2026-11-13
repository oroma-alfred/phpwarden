<?php
/**
 * WP-CLI commands.
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Connect this site to phpwarden and send reports.
 */
class PHPWarden_CLI {

	/**
	 * Store the project token and send the first report.
	 *
	 * ## OPTIONS
	 *
	 * <token>
	 * : The project ingest token from your phpwarden dashboard.
	 *
	 * [--[no-]remote-updates]
	 * : Also allow the phpwarden dashboard to update plugins and themes on this site.
	 *
	 * ## EXAMPLES
	 *
	 *     wp phpwarden activate TOKEN
	 *     wp phpwarden activate TOKEN --remote-updates
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Flags.
	 */
	public function activate( $args, $assoc_args ) {
		$this->require_main_site();

		if ( PHPWarden_Settings::token_is_constant() ) {
			WP_CLI::warning( 'PHPWARDEN_TOKEN is defined in wp-config.php; the token argument was ignored.' );
		} elseif ( ! PHPWarden_Settings::set_token( isset( $args[0] ) ? $args[0] : '' ) ) {
			WP_CLI::error( 'That does not look like a valid token.' );
		}

		// --remote-updates turns them on, --no-remote-updates turns them off;
		// with neither flag the current setting is left alone.
		if ( array_key_exists( 'remote-updates', $assoc_args ) ) {
			if ( PHPWarden_Settings::remote_is_constant() ) {
				WP_CLI::warning( 'PHPWARDEN_REMOTE_UPDATES is defined in wp-config.php; the flag was ignored.' );
			} else {
				PHPWarden_Settings::set_remote_updates( ! empty( $assoc_args['remote-updates'] ) );
			}
		}

		PHPWarden_Plugin::ensure_schedule();
		$this->report( PHPWarden_Client::sync( 'cli' ) );
	}

	/**
	 * Send a report now.
	 */
	public function sync() {
		$this->require_main_site();
		$this->report( PHPWarden_Client::sync( 'cli' ) );
	}

	/**
	 * Show configuration and the last sync result.
	 */
	public function status() {
		$token  = PHPWarden_Settings::get_token();
		$status = PHPWarden_Settings::get_status();
		$next   = wp_next_scheduled( PHPWarden_Plugin::CRON_HOOK );

		WP_CLI::line( 'Token:          ' . ( '' === $token ? '(not set)' : PHPWarden_Settings::mask_token( $token ) ) . ( PHPWarden_Settings::token_is_constant() ? ' (wp-config.php)' : '' ) );
		WP_CLI::line( 'API:            ' . PHPWarden_Settings::get_api_base() );
		WP_CLI::line( 'Remote updates: ' . ( PHPWarden_Settings::remote_updates_enabled() ? 'enabled' : 'disabled' ) . ( PHPWarden_Settings::remote_is_constant() ? ' (wp-config.php)' : '' ) );
		WP_CLI::line( 'Next report:    ' . ( $next ? gmdate( 'Y-m-d H:i:s', $next ) . ' UTC' : '(not scheduled)' ) );
		if ( empty( $status['time'] ) ) {
			WP_CLI::line( 'Last sync:      never' );
			return;
		}
		WP_CLI::line( 'Last sync:      ' . gmdate( 'Y-m-d H:i:s', (int) $status['time'] ) . ' UTC' );
		WP_CLI::line( 'Result:         ' . ( ! empty( $status['ok'] ) ? 'OK' : 'failed: ' . ( isset( $status['message'] ) ? $status['message'] : '' ) ) );
		if ( isset( $status['exposed'] ) ) {
			WP_CLI::line( 'Exposed:        ' . (int) $status['exposed'] );
			WP_CLI::line( 'KEV:            ' . (int) $status['kev'] );
		}
	}

	/**
	 * Print a sync result.
	 *
	 * @param array $status Status from PHPWarden_Client::sync().
	 */
	private function report( array $status ) {
		if ( empty( $status['ok'] ) ) {
			WP_CLI::error( 'Report failed: ' . $status['message'] );
		}
		WP_CLI::success( sprintf( 'Report sent. Exposed: %d, KEV: %d.', $status['exposed'], $status['kev'] ) );
	}

	/**
	 * On multisite only the main site reports.
	 */
	private function require_main_site() {
		if ( ! PHPWarden_Plugin::should_run() ) {
			WP_CLI::error( 'On multisite, phpwarden runs on the main site of the network only. Re-run without --url or with the main site URL.' );
		}
	}
}
