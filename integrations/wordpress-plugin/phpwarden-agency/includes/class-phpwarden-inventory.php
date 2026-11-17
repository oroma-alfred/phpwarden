<?php
/**
 * Inventory collection.
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the POST /v1/inventory payload.
 */
class PHPWarden_Inventory {

	/**
	 * Largest request body the agent will send. The server limit is 512 KB.
	 */
	const MAX_BYTES = 400000;

	/**
	 * Slug of a plugin: its directory name, or the file stem for single-file plugins.
	 *
	 * @param string $file Plugin file relative to the plugins directory.
	 * @return string
	 */
	public static function plugin_slug( $file ) {
		$file = (string) $file;
		if ( false !== strpos( $file, '/' ) ) {
			return (string) strtok( $file, '/' );
		}
		return preg_replace( '/\.php$/i', '', $file );
	}

	/**
	 * Newer version from an update transient entry, else null.
	 *
	 * @param mixed  $transient `update_plugins` / `update_themes` site transient.
	 * @param string $key       Plugin file or theme stylesheet.
	 * @param string $current   Installed version.
	 * @return string|null
	 */
	public static function update_version( $transient, $key, $current ) {
		if ( ! is_object( $transient ) || empty( $transient->response ) || ! is_array( $transient->response ) ) {
			return null;
		}
		if ( ! isset( $transient->response[ $key ] ) ) {
			return null;
		}
		$item = $transient->response[ $key ];
		$new  = null;
		if ( is_object( $item ) && isset( $item->new_version ) ) {
			$new = $item->new_version;
		} elseif ( is_array( $item ) && isset( $item['new_version'] ) ) {
			$new = $item['new_version'];
		}
		if ( ! is_scalar( $new ) || '' === (string) $new ) {
			return null;
		}
		$new = self::clip( $new, 64 );
		if ( '' !== (string) $current && version_compare( $new, (string) $current, '<=' ) ) {
			return null;
		}
		return $new;
	}

	/**
	 * Plugin rows.
	 *
	 * @param array    $plugins   Result of get_plugins().
	 * @param callable $is_active Receives the plugin file, returns bool.
	 * @param mixed    $updates   `update_plugins` site transient.
	 * @return array[]
	 */
	public static function build_plugins( array $plugins, $is_active, $updates ) {
		$rows = array();
		foreach ( $plugins as $file => $data ) {
			$file    = (string) $file;
			$version = isset( $data['Version'] ) ? self::clip( $data['Version'], 64 ) : '';
			$name    = isset( $data['Name'] ) && '' !== (string) $data['Name'] ? $data['Name'] : self::plugin_slug( $file );
			$rows[]  = array(
				'slug'    => self::plugin_slug( $file ),
				'file'    => $file,
				'name'    => self::clip( $name, 200 ),
				'version' => $version,
				'active'  => (bool) call_user_func( $is_active, $file ),
				'update'  => self::update_version( $updates, $file, $version ),
			);
		}
		return $rows;
	}

	/**
	 * Theme rows.
	 *
	 * @param array    $themes  Result of wp_get_themes(), keyed by stylesheet.
	 * @param string[] $active  Active stylesheet and (for child themes) its parent template.
	 * @param mixed    $updates `update_themes` site transient.
	 * @return array[]
	 */
	public static function build_themes( array $themes, array $active, $updates ) {
		$rows = array();
		foreach ( $themes as $slug => $theme ) {
			$slug    = (string) $slug;
			$version = self::clip( $theme->get( 'Version' ), 64 );
			$name    = $theme->get( 'Name' );
			$rows[]  = array(
				'slug'    => $slug,
				'name'    => self::clip( '' !== (string) $name ? $name : $slug, 200 ),
				'version' => $version,
				'active'  => in_array( $slug, $active, true ),
				'update'  => self::update_version( $updates, $slug, $version ),
			);
		}
		return $rows;
	}

	/**
	 * Collect the full inventory from this WordPress install.
	 *
	 * @param bool $remote_updates Whether the owner enabled remote updates.
	 * @return array Payload for POST /v1/inventory.
	 */
	/**
	 * Whether WordPress's cached update list can be trusted as-is.
	 *
	 * WordPress deletes the `update_plugins` / `update_themes` transient whenever a
	 * plugin or theme is installed, updated or removed, which is exactly when this
	 * agent reports. An empty or old list would tell the dashboard that nothing
	 * has an update waiting.
	 *
	 * @param mixed $transient Site transient value.
	 * @param int   $now       Current unix time.
	 * @return bool
	 */
	public static function updates_are_fresh( $transient, $now ) {
		return is_object( $transient )
			&& ! empty( $transient->last_checked )
			&& ( $now - (int) $transient->last_checked ) < 12 * 3600
			&& isset( $transient->checked ) && is_array( $transient->checked );
	}

	/**
	 * The update list, refreshed from wordpress.org first when it is missing or stale.
	 *
	 * @param string $name `update_plugins` or `update_themes`.
	 * @return mixed
	 */
	public static function fresh_updates( $name ) {
		$transient = get_site_transient( $name );
		if ( self::updates_are_fresh( $transient, time() ) ) {
			return $transient;
		}
		if ( ! function_exists( 'wp_update_plugins' ) ) {
			require_once ABSPATH . WPINC . '/update.php';
		}
		if ( 'update_plugins' === $name ) {
			wp_update_plugins();
		} else {
			wp_update_themes();
		}
		return get_site_transient( $name );
	}

	public static function collect( $remote_updates ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$active_themes = array_values( array_unique( array( (string) get_stylesheet(), (string) get_template() ) ) );

		return array(
			'agent'          => 'phpwarden-wp/' . PHPWARDEN_VERSION,
			'site_url'       => (string) home_url(),
			'php'            => array(
				'version' => PHP_VERSION,
				'sapi'    => php_sapi_name(),
			),
			'wordpress'      => array(
				'core'    => self::core_version(),
				'plugins' => self::build_plugins(
					get_plugins(),
					array( __CLASS__, 'is_plugin_active' ),
					self::fresh_updates( 'update_plugins' )
				),
				'themes'  => self::build_themes(
					wp_get_themes(),
					$active_themes,
					self::fresh_updates( 'update_themes' )
				),
			),
			'remote_updates' => (bool) $remote_updates,
		);
	}

	/**
	 * Active on this site or network-active.
	 *
	 * @param string $file Plugin file.
	 * @return bool
	 */
	public static function is_plugin_active( $file ) {
		return is_plugin_active( $file ) || ( is_multisite() && is_plugin_active_for_network( $file ) );
	}

	/**
	 * WordPress core version, unaffected by `bloginfo` filters.
	 *
	 * @return string
	 */
	public static function core_version() {
		if ( function_exists( 'wp_get_wp_version' ) ) {
			return (string) wp_get_wp_version();
		}
		return isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '';
	}

	/**
	 * JSON-encode the payload, keeping it under MAX_BYTES. Display names are
	 * dropped first if the body is too large.
	 *
	 * @param array $payload Payload from collect().
	 * @return string|false JSON, or false when it cannot be made small enough.
	 */
	public static function encode( array $payload ) {
		$json = wp_json_encode( $payload );
		if ( is_string( $json ) && strlen( $json ) <= self::MAX_BYTES ) {
			return $json;
		}
		foreach ( array( 'plugins', 'themes' ) as $kind ) {
			foreach ( $payload['wordpress'][ $kind ] as $i => $row ) {
				$payload['wordpress'][ $kind ][ $i ]['name'] = $row['slug'];
			}
		}
		$json = wp_json_encode( $payload );
		if ( is_string( $json ) && strlen( $json ) <= self::MAX_BYTES ) {
			return $json;
		}
		return false;
	}

	/**
	 * Plain-text, length-limited string.
	 *
	 * @param mixed $value Value.
	 * @param int   $max   Maximum characters.
	 * @return string
	 */
	private static function clip( $value, $max ) {
		$value = is_scalar( $value ) ? trim( wp_strip_all_tags( (string) $value ) ) : '';
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $value, 0, $max );
		}
		return substr( $value, 0, $max );
	}
}
