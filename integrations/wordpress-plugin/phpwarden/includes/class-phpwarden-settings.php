<?php
/**
 * Stored settings, consent and status.
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
	const OPT_REMOTE  = 'phpwarden_remote_updates'; // older versions only; removed on uninstall.
	const OPT_STATUS  = 'phpwarden_status';
	const OPT_CONSENT = 'phpwarden_consent';
	const OPT_LOG     = 'phpwarden_log'; // older versions only; removed on uninstall.
	const OPT_USAGE   = 'phpwarden_usage_consent';
	const DEFAULT_API = 'https://app.phpwarden.io';

	/**
	 * All option names (used by uninstall).
	 *
	 * @return string[]
	 */
	public static function option_names() {
		return array( self::OPT_TOKEN, self::OPT_API, self::OPT_REMOTE, self::OPT_STATUS, self::OPT_LOG, self::OPT_CONSENT, self::OPT_USAGE );
	}

	/* ---------- consent ---------- */

	/**
	 * Whether an administrator has explicitly agreed to send reports.
	 * Nothing is ever sent without it, whatever else is configured.
	 *
	 * @return bool
	 */
	public static function has_consent() {
		return '1' === (string) get_option( self::OPT_CONSENT, '' );
	}

	/**
	 * Record or withdraw consent.
	 *
	 * @param bool $on Consent given.
	 */
	public static function set_consent( $on ) {
		if ( $on ) {
			update_option( self::OPT_CONSENT, '1', true ); // autoloaded: checked on every request.
		} else {
			delete_option( self::OPT_CONSENT );
		}
	}

	/**
	 * Whether an administrator also agreed to send usage names (shortcodes,
	 * blocks, REST namespaces, AJAX action names) for reachability. Separate,
	 * off by default, and only meaningful when the main consent is given.
	 *
	 * @return bool
	 */
	public static function has_usage_consent() {
		return self::has_consent() && '1' === (string) get_option( self::OPT_USAGE, '' );
	}

	/**
	 * Record or withdraw the usage-names consent.
	 *
	 * @param bool $on Consent given.
	 */
	public static function set_usage_consent( $on ) {
		if ( $on ) {
			update_option( self::OPT_USAGE, '1', false );
		} else {
			delete_option( self::OPT_USAGE );
		}
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

	/* ---------- status ---------- */

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
}
