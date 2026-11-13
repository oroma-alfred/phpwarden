<?php
/**
 * Remote command validation and execution.
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Validates commands returned by the server and runs them with WordPress's own
 * upgrader. Nothing the server sends is ever used as a URL or filesystem path:
 * a command only selects an already-installed plugin or theme by its local key.
 */
class PHPWarden_Commands {

	const MAX_PER_SYNC = 5;

	/**
	 * Allowed actions. Nothing else, ever.
	 *
	 * @return string[]
	 */
	public static function allowed_actions() {
		return array( 'update_plugin', 'update_theme', 'deactivate_plugin' );
	}

	/**
	 * Commands to consider for this sync: none when remote updates are off,
	 * otherwise at most MAX_PER_SYNC.
	 *
	 * @param mixed $commands       `commands` from the server response.
	 * @param bool  $remote_enabled Whether the owner enabled remote updates.
	 * @return array
	 */
	public static function select( $commands, $remote_enabled ) {
		if ( true !== $remote_enabled || ! is_array( $commands ) ) {
			return array();
		}
		return array_slice( array_values( $commands ), 0, self::MAX_PER_SYNC );
	}

	/**
	 * Whether a command id is safe to place in a request path.
	 *
	 * @param mixed $id Command id.
	 * @return bool
	 */
	public static function valid_id( $id ) {
		return is_string( $id ) && 1 === preg_match( '/^[A-Za-z0-9_-]{1,64}$/', $id );
	}

	/**
	 * Validate one command against what is installed locally.
	 *
	 * @param mixed    $command        Command from the server.
	 * @param bool     $remote_enabled Whether the owner enabled remote updates.
	 * @param string[] $plugin_files   Keys of get_plugins().
	 * @param string[] $theme_slugs    Keys of wp_get_themes().
	 * @param string   $self_file      This plugin's own file (cannot be deactivated remotely).
	 * @return array { valid: bool, reason: string, id, action, slug, target } where
	 *               `target` is the LOCAL plugin file / theme stylesheet key.
	 */
	public static function validate( $command, $remote_enabled, array $plugin_files, array $theme_slugs, $self_file = '' ) {
		$out = array(
			'valid'  => false,
			'reason' => '',
			'id'     => '',
			'action' => '',
			'slug'   => '',
			'target' => '',
		);
		if ( true !== $remote_enabled ) {
			$out['reason'] = 'remote_updates_disabled';
			return $out;
		}
		if ( ! is_array( $command ) ) {
			$out['reason'] = 'malformed';
			return $out;
		}
		if ( ! isset( $command['id'] ) || ! self::valid_id( $command['id'] ) ) {
			$out['reason'] = 'bad_id';
			return $out;
		}
		$out['id'] = $command['id'];

		$action = isset( $command['action'] ) && is_string( $command['action'] ) ? $command['action'] : '';
		if ( ! in_array( $action, self::allowed_actions(), true ) ) {
			$out['reason'] = 'unknown_action';
			return $out;
		}
		$out['action'] = $action;

		$slug = isset( $command['slug'] ) && is_string( $command['slug'] ) ? $command['slug'] : '';
		if ( '' === $slug || strlen( $slug ) > 200 ) {
			$out['reason'] = 'unknown_slug';
			return $out;
		}

		if ( 'update_theme' === $action ) {
			$index = array_search( $slug, array_map( 'strval', $theme_slugs ), true );
			if ( false === $index ) {
				$out['reason'] = 'unknown_slug';
				return $out;
			}
			$out['slug']   = (string) $theme_slugs[ $index ];
			$out['target'] = (string) $theme_slugs[ $index ];
			$out['valid']  = true;
			return $out;
		}

		// Plugin actions: resolve to a local get_plugins() key.
		$target = '';
		if ( isset( $command['file'] ) && '' !== $command['file'] ) {
			if ( ! is_string( $command['file'] ) ) {
				$out['reason'] = 'unknown_file';
				return $out;
			}
			$index = array_search( $command['file'], array_map( 'strval', $plugin_files ), true );
			if ( false === $index ) {
				$out['reason'] = 'unknown_file';
				return $out;
			}
			$target = (string) $plugin_files[ $index ];
			if ( PHPWarden_Inventory::plugin_slug( $target ) !== $slug ) {
				$out['reason'] = 'slug_file_mismatch';
				return $out;
			}
		} else {
			$matches = array();
			foreach ( $plugin_files as $file ) {
				if ( PHPWarden_Inventory::plugin_slug( $file ) === $slug ) {
					$matches[] = (string) $file;
				}
			}
			if ( 1 !== count( $matches ) ) {
				$out['reason'] = empty( $matches ) ? 'unknown_slug' : 'ambiguous_slug';
				return $out;
			}
			$target = $matches[0];
		}

		if ( 'deactivate_plugin' === $action && '' !== $self_file && $target === $self_file ) {
			$out['reason'] = 'cannot_deactivate_agent';
			return $out;
		}

		$out['slug']   = PHPWarden_Inventory::plugin_slug( $target );
		$out['target'] = $target;
		$out['valid']  = true;
		return $out;
	}

	/**
	 * Run a validated command.
	 *
	 * @param array $cmd Result of validate() with valid === true.
	 * @return array { ok: bool, from: string, to: string, message: string }
	 */
	public static function execute( array $cmd ) {
		if ( empty( $cmd['valid'] ) || ! PHPWarden_Settings::remote_updates_enabled() ) {
			return self::result( false, '', '', 'not permitted' );
		}
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		if ( 'deactivate_plugin' === $cmd['action'] ) {
			return self::deactivate_plugin( $cmd['target'] );
		}

		if ( function_exists( 'wp_is_file_mod_allowed' ) && ! wp_is_file_mod_allowed( 'phpwarden_remote_update' ) ) {
			return self::result( false, '', '', 'file modifications are disabled on this site' );
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/theme.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

		if ( 'update_plugin' === $cmd['action'] ) {
			return self::update_plugin( $cmd['target'] );
		}
		if ( 'update_theme' === $cmd['action'] ) {
			return self::update_theme( $cmd['target'] );
		}
		return self::result( false, '', '', 'unknown action' );
	}

	/**
	 * Update one installed plugin to the version wordpress.org offers.
	 *
	 * @param string $local_file Key of get_plugins().
	 * @return array
	 */
	private static function update_plugin( $local_file ) {
		$from = self::plugin_version( $local_file );
		if ( null === $from ) {
			return self::result( false, '', '', 'plugin is not installed' );
		}
		wp_update_plugins();
		$offered = PHPWarden_Inventory::update_version( get_site_transient( 'update_plugins' ), $local_file, $from );
		if ( null === $offered ) {
			return self::result( false, $from, $from, 'no update available from WordPress' );
		}

		$skin     = new Automatic_Upgrader_Skin();
		$upgrader = new Plugin_Upgrader( $skin );
		$results  = $upgrader->bulk_upgrade( array( $local_file ) );
		$outcome  = is_array( $results ) && isset( $results[ $local_file ] ) ? $results[ $local_file ] : false;

		wp_clean_plugins_cache( false );
		$to = self::plugin_version( $local_file );
		$to = null === $to ? '' : $to;

		return self::upgrade_result( $outcome, $skin, $from, $to );
	}

	/**
	 * Update one installed theme to the version wordpress.org offers.
	 *
	 * @param string $local_slug Key of wp_get_themes().
	 * @return array
	 */
	private static function update_theme( $local_slug ) {
		$theme = wp_get_theme( $local_slug );
		if ( ! $theme->exists() ) {
			return self::result( false, '', '', 'theme is not installed' );
		}
		$from = (string) $theme->get( 'Version' );
		wp_update_themes();
		$offered = PHPWarden_Inventory::update_version( get_site_transient( 'update_themes' ), $local_slug, $from );
		if ( null === $offered ) {
			return self::result( false, $from, $from, 'no update available from WordPress' );
		}

		$skin     = new Automatic_Upgrader_Skin();
		$upgrader = new Theme_Upgrader( $skin );
		$results  = $upgrader->bulk_upgrade( array( $local_slug ) );
		$outcome  = is_array( $results ) && isset( $results[ $local_slug ] ) ? $results[ $local_slug ] : false;

		wp_clean_themes_cache();
		$to = (string) wp_get_theme( $local_slug )->get( 'Version' );

		return self::upgrade_result( $outcome, $skin, $from, $to );
	}

	/**
	 * Deactivate one installed plugin.
	 *
	 * @param string $local_file Key of get_plugins().
	 * @return array
	 */
	private static function deactivate_plugin( $local_file ) {
		$version = self::plugin_version( $local_file );
		if ( null === $version ) {
			return self::result( false, '', '', 'plugin is not installed' );
		}
		if ( ! PHPWarden_Inventory::is_plugin_active( $local_file ) ) {
			return self::result( true, $version, $version, 'already inactive' );
		}
		deactivate_plugins( $local_file );
		$ok = ! PHPWarden_Inventory::is_plugin_active( $local_file );
		return self::result( $ok, $version, $version, $ok ? 'deactivated' : 'could not deactivate' );
	}

	/**
	 * Installed version of a plugin, or null when it is not installed.
	 *
	 * @param string $local_file Key of get_plugins().
	 * @return string|null
	 */
	private static function plugin_version( $local_file ) {
		$plugins = get_plugins();
		if ( ! isset( $plugins[ $local_file ] ) ) {
			return null;
		}
		return isset( $plugins[ $local_file ]['Version'] ) ? (string) $plugins[ $local_file ]['Version'] : '';
	}

	/**
	 * Turn an upgrader outcome into a result.
	 *
	 * @param mixed  $outcome Per-item result of bulk_upgrade().
	 * @param object $skin    Upgrader skin.
	 * @param string $from    Version before.
	 * @param string $to      Version after.
	 * @return array
	 */
	private static function upgrade_result( $outcome, $skin, $from, $to ) {
		if ( is_wp_error( $outcome ) ) {
			return self::result( false, $from, $to, $outcome->get_error_message() );
		}
		if ( is_wp_error( $skin->result ) ) {
			return self::result( false, $from, $to, $skin->result->get_error_message() );
		}
		if ( empty( $outcome ) || $to === $from ) {
			$messages = method_exists( $skin, 'get_upgrade_messages' ) ? (array) $skin->get_upgrade_messages() : array();
			$last     = empty( $messages ) ? 'update failed' : (string) end( $messages );
			return self::result( false, $from, $to, $last );
		}
		return self::result( true, $from, $to, '' );
	}

	/**
	 * Build a result array.
	 *
	 * @param bool   $ok      Success.
	 * @param string $from    Version before.
	 * @param string $to      Version after.
	 * @param string $message Message.
	 * @return array
	 */
	public static function result( $ok, $from, $to, $message ) {
		return array(
			'ok'      => (bool) $ok,
			'from'    => (string) $from,
			'to'      => (string) $to,
			'message' => substr( trim( wp_strip_all_tags( (string) $message ) ), 0, 500 ),
		);
	}
}
