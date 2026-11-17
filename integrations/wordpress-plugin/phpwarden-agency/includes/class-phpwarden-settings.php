<?php
/**
 * Stored settings, status and command log.
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads and writes the plugin's options. No hooks are registered here.
 */
class PHPWarden_Settings {

	const OPT_TOKEN   = 'phpwarden_token';
	const OPT_API     = 'phpwarden_api_base';
	const OPT_REMOTE  = 'phpwarden_remote_updates';
	const OPT_STATUS  = 'phpwarden_status';
	const OPT_LOG     = 'phpwarden_log';
	const DEFAULT_API = 'https://app.phpwarden.io';
	const LOG_MAX     = 50;

	/**
	 * All option names (used by uninstall).
	 *
	 * @return string[]
	 */
	public static function option_names() {
		return array( self::OPT_TOKEN, self::OPT_API, self::OPT_REMOTE, self::OPT_STATUS, self::OPT_LOG );
	}

	/* ---------- token ---------- */

	/**
	 * Whether the token comes from wp-config.php.
	 *
	 * @return bool
	 */
	public static function token_is_constant() {
		return defined( 'PHPWARDEN_TOKEN' );
	}

	/**
	 * The project token ('' when not configured).
	 *
	 * @return string
	 */
	public static function get_token() {
		if ( self::token_is_constant() ) {
			return self::sanitize_token( constant( 'PHPWARDEN_TOKEN' ) );
		}
		return self::sanitize_token( get_option( self::OPT_TOKEN, '' ) );
	}

	/**
	 * Store the token.
	 *
	 * @param string $raw Raw token.
	 * @return bool False when the value is not a usable token.
	 */
	public static function set_token( $raw ) {
		$token = self::sanitize_token( $raw );
		if ( '' === $token ) {
			return false;
		}
		update_option( self::OPT_TOKEN, $token, false );
		return true;
	}

	/**
	 * Remove the stored token.
	 */
	public static function delete_token() {
		delete_option( self::OPT_TOKEN );
	}

	/**
	 * Keep only characters that can appear in a bearer token.
	 *
	 * @param mixed $raw Raw value.
	 * @return string
	 */
	public static function sanitize_token( $raw ) {
		if ( ! is_string( $raw ) ) {
			return '';
		}
		$token = preg_replace( '/[^A-Za-z0-9._~+\/=:-]/', '', trim( $raw ) );
		return substr( (string) $token, 0, 255 );
	}

	/**
	 * Mask a token for display: only the last 4 characters are shown.
	 * Tokens shorter than 8 characters are fully masked.
	 *
	 * @param string $token Token.
	 * @return string
	 */
	public static function mask_token( $token ) {
		$token = (string) $token;
		if ( '' === $token ) {
			return '';
		}
		$mask = str_repeat( '*', 8 );
		if ( strlen( $token ) < 8 ) {
			return $mask;
		}
		return $mask . substr( $token, -4 );
	}

	/* ---------- API base ---------- */

	/**
	 * Whether the API base comes from wp-config.php.
	 *
	 * @return bool
	 */
	public static function api_is_constant() {
		return defined( 'PHPWARDEN_API' );
	}

	/**
	 * API base URL without trailing slash. Constant, then option, then default; filterable.
	 *
	 * @return string
	 */
	public static function get_api_base() {
		$base = '';
		if ( self::api_is_constant() ) {
			$base = self::sanitize_api_base( constant( 'PHPWARDEN_API' ) );
		} else {
			$base = self::sanitize_api_base( get_option( self::OPT_API, '' ) );
		}
		if ( '' === $base ) {
			$base = self::DEFAULT_API;
		}
		/**
		 * Filters the phpwarden API base URL.
		 *
		 * @param string $base Base URL, no trailing slash.
		 */
		$filtered = self::sanitize_api_base( apply_filters( 'phpwarden_api_base', $base ) );
		return '' === $filtered ? $base : $filtered;
	}

	/**
	 * Validate an API base URL. HTTPS is required, except for local development hosts.
	 *
	 * @param mixed $raw Raw value.
	 * @return string Normalised URL, or '' when invalid.
	 */
	public static function sanitize_api_base( $raw ) {
		if ( ! is_string( $raw ) ) {
			return '';
		}
		$raw = trim( $raw );
		if ( '' === $raw || strlen( $raw ) > 255 || preg_match( '/[\s<>"\'\\\\]/', $raw ) ) {
			return '';
		}
		$parts = wp_parse_url( $raw );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) || isset( $parts['query'] ) || isset( $parts['fragment'] ) ) {
			return '';
		}
		$scheme = strtolower( $parts['scheme'] );
		$host   = strtolower( $parts['host'] );
		$local  = in_array( $host, array( 'localhost', '127.0.0.1', '[::1]' ), true )
			|| '.localhost' === substr( $host, -10 )
			|| '.test' === substr( $host, -5 );
		if ( 'https' !== $scheme && ! ( 'http' === $scheme && $local ) ) {
			return '';
		}
		$url = $scheme . '://' . $host;
		if ( ! empty( $parts['port'] ) ) {
			$url .= ':' . (int) $parts['port'];
		}
		if ( ! empty( $parts['path'] ) ) {
			$url .= rtrim( $parts['path'], '/' );
		}
		return $url;
	}

	/**
	 * Store the API base. An empty or invalid value resets to the default.
	 *
	 * @param string $raw Raw URL.
	 */
	public static function set_api_base( $raw ) {
		$base = self::sanitize_api_base( $raw );
		if ( '' === $base || self::DEFAULT_API === $base ) {
			delete_option( self::OPT_API );
			return;
		}
		update_option( self::OPT_API, $base, false );
	}

	/* ---------- remote updates ---------- */

	/**
	 * Whether the remote-updates switch comes from wp-config.php.
	 *
	 * @return bool
	 */
	public static function remote_is_constant() {
		return defined( 'PHPWARDEN_REMOTE_UPDATES' );
	}

	/**
	 * Whether the site owner allowed remote updates. Off unless explicitly enabled.
	 *
	 * @return bool
	 */
	public static function remote_updates_enabled() {
		if ( self::remote_is_constant() ) {
			return true === constant( 'PHPWARDEN_REMOTE_UPDATES' );
		}
		return '1' === (string) get_option( self::OPT_REMOTE, '0' );
	}

	/**
	 * Store the remote-updates switch.
	 *
	 * @param bool $enabled Enabled.
	 */
	public static function set_remote_updates( $enabled ) {
		update_option( self::OPT_REMOTE, $enabled ? '1' : '0', false );
	}

	/* ---------- status + log ---------- */

	/**
	 * Last sync status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$status = get_option( self::OPT_STATUS, array() );
		return is_array( $status ) ? $status : array();
	}

	/**
	 * Store the last sync status.
	 *
	 * @param array $status Status.
	 */
	public static function set_status( array $status ) {
		update_option( self::OPT_STATUS, $status, false );
	}

	/**
	 * Command log, newest first.
	 *
	 * @return array[]
	 */
	public static function get_log() {
		$log = get_option( self::OPT_LOG, array() );
		return is_array( $log ) ? array_values( $log ) : array();
	}

	/**
	 * Prepend an entry to the command log and cap it.
	 *
	 * @param array $entry Keys: time, action, slug, ok, message, from, to.
	 */
	public static function add_log( array $entry ) {
		$log = self::get_log();
		array_unshift( $log, $entry );
		update_option( self::OPT_LOG, array_slice( $log, 0, self::LOG_MAX ), false );
	}
}
