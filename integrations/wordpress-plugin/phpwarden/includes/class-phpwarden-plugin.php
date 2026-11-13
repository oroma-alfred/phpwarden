<?php
/**
 * Hooks: cron schedule and change triggers.
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the plugin into WordPress.
 */
class PHPWarden_Plugin {

	const CRON_HOOK   = 'phpwarden_sync';
	const SINGLE_HOOK = 'phpwarden_sync_soon';
	const DEBOUNCE    = 60;

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'cron_sync' ) );
		add_action( self::SINGLE_HOOK, array( __CLASS__, 'change_sync' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ) );

		foreach ( array( 'upgrader_process_complete', 'activated_plugin', 'deactivated_plugin', 'deleted_plugin', 'switch_theme', 'deleted_theme' ) as $hook ) {
			add_action( $hook, array( __CLASS__, 'schedule_soon' ), 20, 0 );
		}
	}

	/**
	 * On multisite only the network's main site reports.
	 *
	 * @return bool
	 */
	public static function should_run() {
		return ! is_multisite() || is_main_site();
	}

	/**
	 * Capability needed to manage the plugin.
	 *
	 * @return string
	 */
	public static function capability() {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	/**
	 * Activation: schedule the twice-daily report.
	 */
	public static function activate() {
		self::ensure_schedule();
	}

	/**
	 * Make sure the recurring event exists (also covers network activation).
	 */
	public static function ensure_schedule() {
		if ( self::should_run() && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + 5 * MINUTE_IN_SECONDS, 'twicedaily', self::CRON_HOOK );
		}
	}

	/**
	 * Deactivation: clear cron events.
	 */
	public static function deactivate() {
		$switched = false;
		if ( is_multisite() && ! is_main_site() ) {
			switch_to_blog( get_main_site_id() );
			$switched = true;
		}
		wp_clear_scheduled_hook( self::CRON_HOOK );
		wp_clear_scheduled_hook( self::SINGLE_HOOK );
		delete_transient( PHPWarden_Client::LOCK );
		if ( $switched ) {
			restore_current_blog();
		}
	}

	/**
	 * Debounced report after a plugin/theme change.
	 */
	public static function schedule_soon() {
		if ( ! self::should_run() || '' === PHPWarden_Settings::get_token() ) {
			return;
		}
		if ( ! wp_next_scheduled( self::SINGLE_HOOK ) ) {
			wp_schedule_single_event( time() + self::DEBOUNCE, self::SINGLE_HOOK );
		}
	}

	/**
	 * Twice-daily cron callback.
	 */
	public static function cron_sync() {
		if ( self::should_run() && '' !== PHPWarden_Settings::get_token() ) {
			PHPWarden_Client::sync( 'cron' );
		}
	}

	/**
	 * Debounced cron callback.
	 */
	public static function change_sync() {
		if ( self::should_run() && '' !== PHPWarden_Settings::get_token() ) {
			PHPWarden_Client::sync( 'change' );
		}
	}
}
