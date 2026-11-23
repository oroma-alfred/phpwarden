<?php
/**
 * Health check and file rollback around a remote update.
 *
 * Runs only inside PHPWarden_Commands::execute(), which itself runs only when the
 * site administrator turned on remote updates. Files only: the database is never
 * read, changed or restored here.
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pure checks (unit tested) plus the WordPress-side backup, restore and fetch.
 */
class PHPWarden_Safe_Update {

	const BACKUP_DIR   = 'phpwarden-backups';
	const MIN_BASELINE = 2048; // Bytes. Below this the size rule is not applied.
	const SHRINK_RATIO = 0.5;  // A homepage less than half its baseline size fails.

	/**
	 * Whether a requested exact version is acceptable.
	 *
	 * @param mixed $version Version from the server.
	 * @return bool
	 */
	public static function valid_version( $version ) {
		return is_string( $version ) && 1 === preg_match( '/^[0-9][0-9A-Za-z.+-]{0,39}$/', $version );
	}

	/**
	 * Package URL for an exact version. Always WordPress.org: the server only
	 * chooses a version number, never a URL.
	 *
	 * @param string $kind    plugin|theme.
	 * @param string $slug    WordPress.org slug (directory name).
	 * @param string $version Exact version.
	 * @return string Empty when the input is not acceptable.
	 */
	public static function package_url( $kind, $slug, $version ) {
		if ( ! in_array( $kind, array( 'plugin', 'theme' ), true ) || 1 !== preg_match( '/^[a-z0-9][a-z0-9._-]{0,99}$/', $slug ) || ! self::valid_version( $version ) ) {
			return '';
		}
		return 'https://downloads.wordpress.org/' . $kind . '/' . $slug . '.' . $version . '.zip';
	}

	/**
	 * Whether a response body shows a PHP fatal error.
	 *
	 * @param string $body Response body.
	 * @return bool
	 */
	public static function has_fatal( $body ) {
		$body = (string) $body;
		foreach ( array( 'There has been a critical error on this website', 'There has been a critical error on your website', 'Fatal error</b>:', 'PHP Fatal error', 'Fatal error: Uncaught' ) as $needle ) {
			if ( false !== stripos( $body, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Compare a probe taken after the update with the baseline taken before.
	 *
	 * Each probe: array( 'home' => array( code, body_len, fatal ), 'admin' => array( code, body_len, fatal ) ).
	 *
	 * @param array $before Baseline probe.
	 * @param array $after  Probe after the update.
	 * @return string 'ok' or the reason it failed.
	 */
	public static function evaluate( array $before, array $after ) {
		foreach ( array( 'home' => 'homepage', 'admin' => 'wp-admin' ) as $key => $label ) {
			$a = isset( $after[ $key ] ) ? $after[ $key ] : array();
			$b = isset( $before[ $key ] ) ? $before[ $key ] : array();
			$code = isset( $a['code'] ) ? (int) $a['code'] : 0;
			// Only a page that was healthy before can be blamed on the update.
			$was_ok = isset( $b['code'] ) && 200 === (int) $b['code'];
			if ( 200 !== $code && $was_ok ) {
				return 0 === $code ? $label . ' did not respond' : $label . ' returned HTTP ' . $code;
			}
			if ( ! empty( $a['fatal'] ) && empty( $b['fatal'] ) ) {
				return 'PHP fatal error on the ' . $label;
			}
		}
		$base = isset( $before['home']['len'] ) ? (int) $before['home']['len'] : 0;
		$now  = isset( $after['home']['len'] ) ? (int) $after['home']['len'] : 0;
		if ( $base >= self::MIN_BASELINE && $now < $base * self::SHRINK_RATIO ) {
			return 'homepage shrank from ' . $base . ' to ' . $now . ' bytes';
		}
		return 'ok';
	}

	/**
	 * Fetch the homepage and wp-admin as an anonymous visitor.
	 * wp-admin redirects to the login page; the final page must be 200.
	 *
	 * @return array Probe for evaluate().
	 */
	public static function probe() {
		$out = array();
		$nonce = wp_generate_password( 8, false );
		$urls  = array(
			'home'  => add_query_arg( 'phpwarden_health', $nonce, home_url( '/' ) ),
			'admin' => admin_url( '/' ),
		);
		foreach ( $urls as $key => $url ) {
			$response = wp_remote_get(
				$url,
				array(
					'timeout'     => 20,
					'redirection' => 5,
					'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
					'user-agent'  => 'phpwarden-wp-health/' . PHPWARDEN_VERSION,
					'headers'     => array( 'Cache-Control' => 'no-cache' ),
				)
			);
			if ( is_wp_error( $response ) ) {
				$out[ $key ] = array(
					'code'  => 0,
					'len'   => 0,
					'fatal' => false,
				);
				continue;
			}
			$body        = (string) wp_remote_retrieve_body( $response );
			$out[ $key ] = array(
				'code'  => (int) wp_remote_retrieve_response_code( $response ),
				'len'   => strlen( $body ),
				'fatal' => self::has_fatal( $body ),
			);
		}
		return $out;
	}

	/**
	 * Directory (or single file) that holds a plugin or theme.
	 *
	 * @param string $kind   plugin|theme.
	 * @param string $target Local plugin file or theme stylesheet.
	 * @return string Absolute path, or '' when unknown.
	 */
	public static function source_path( $kind, $target ) {
		if ( 'theme' === $kind ) {
			$theme = wp_get_theme( $target );
			return $theme->exists() ? untrailingslashit( $theme->get_stylesheet_directory() ) : '';
		}
		$dir = dirname( $target );
		return '.' === $dir ? WP_PLUGIN_DIR . '/' . $target : WP_PLUGIN_DIR . '/' . $dir;
	}

	/**
	 * Copy the installed files to uploads/phpwarden-backups/<random>/ before updating.
	 *
	 * @param string $kind   plugin|theme.
	 * @param string $target Local key.
	 * @return array|WP_Error { src, copy }.
	 */
	public static function backup( $kind, $target ) {
		global $wp_filesystem;
		if ( ! WP_Filesystem() || ! $wp_filesystem ) {
			return new WP_Error( 'phpwarden_fs', 'no filesystem access for a backup' );
		}
		$src = self::source_path( $kind, $target );
		if ( '' === $src || ! $wp_filesystem->exists( $src ) ) {
			return new WP_Error( 'phpwarden_src', 'installed files not found' );
		}
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) ) {
			return new WP_Error( 'phpwarden_uploads', 'uploads folder is not writable' );
		}
		$root = trailingslashit( $uploads['basedir'] ) . self::BACKUP_DIR;
		if ( ! $wp_filesystem->is_dir( $root ) ) {
			$wp_filesystem->mkdir( $root );
			$wp_filesystem->put_contents( $root . '/index.php', "<?php\n// Silence is golden.\n" );
			$wp_filesystem->put_contents( $root . '/.htaccess', "Require all denied\nDeny from all\n" );
		}
		$copy = $root . '/' . wp_generate_password( 16, false );
		if ( ! $wp_filesystem->mkdir( $copy ) ) {
			return new WP_Error( 'phpwarden_mkdir', 'could not create the backup folder' );
		}
		if ( $wp_filesystem->is_dir( $src ) ) {
			$dest = $copy . '/' . basename( $src );
			$wp_filesystem->mkdir( $dest );
			$ok = copy_dir( $src, $dest );
		} else {
			$ok = $wp_filesystem->copy( $src, $copy . '/' . basename( $src ), true );
		}
		if ( true !== $ok ) {
			$wp_filesystem->delete( $copy, true );
			return new WP_Error( 'phpwarden_copy', 'could not copy the installed files' );
		}
		return array(
			'src'  => $src,
			'copy' => $copy . '/' . basename( $src ),
			'root' => $copy,
		);
	}

	/**
	 * Put the backed-up files back. Files only, never the database.
	 *
	 * @param array $backup Result of backup().
	 * @return bool
	 */
	public static function restore( array $backup ) {
		global $wp_filesystem;
		if ( ! WP_Filesystem() || ! $wp_filesystem ) {
			return false;
		}
		if ( $wp_filesystem->exists( $backup['src'] ) ) {
			$wp_filesystem->delete( $backup['src'], true );
		}
		if ( $wp_filesystem->is_dir( $backup['copy'] ) ) {
			$wp_filesystem->mkdir( $backup['src'] );
			$ok = true === copy_dir( $backup['copy'], $backup['src'] );
		} else {
			$ok = $wp_filesystem->copy( $backup['copy'], $backup['src'], true );
		}
		if ( function_exists( 'wp_clean_plugins_cache' ) ) {
			wp_clean_plugins_cache( false );
		}
		if ( function_exists( 'wp_clean_themes_cache' ) ) {
			wp_clean_themes_cache();
		}
		return $ok;
	}

	/**
	 * Remove a backup once it is no longer needed.
	 *
	 * @param array $backup Result of backup().
	 */
	public static function discard( array $backup ) {
		global $wp_filesystem;
		if ( WP_Filesystem() && $wp_filesystem && ! empty( $backup['root'] ) ) {
			$wp_filesystem->delete( $backup['root'], true );
		}
	}
}
