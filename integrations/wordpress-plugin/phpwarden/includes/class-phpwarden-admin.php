<?php
/**
 * Settings page.
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings > phpwarden.
 */
class PHPWarden_Admin {

	const PAGE = 'phpwarden';

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_phpwarden_save', array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_phpwarden_sync', array( __CLASS__, 'handle_sync' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( PHPWARDEN_PLUGIN_FILE ), array( __CLASS__, 'action_links' ) );
		add_action( 'admin_notices', array( __CLASS__, 'setup_notice' ) );
	}

	/**
	 * On the Plugins screen only: say when reports are off because consent is missing
	 * (for example after an upgrade from 1.1.0), or when the plugin is active on a
	 * site of a network that is not the main site, where it does nothing.
	 */
	public static function setup_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'plugins' !== $screen->id ) {
			return;
		}
		if ( ! PHPWarden_Plugin::should_run() ) {
			if ( current_user_can( 'manage_options' ) ) {
				echo '<div class="notice notice-info"><p>' . esc_html__( 'phpwarden reports from the main site of the network only. Activate it on the main site or network-activate it.', 'phpwarden' ) . '</p></div>';
			}
			return;
		}
		if ( ! current_user_can( PHPWarden_Plugin::capability() ) || PHPWarden_Settings::has_consent() || '' === PHPWarden_Settings::get_token() ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>' . esc_html__( 'phpwarden reports are off until an administrator agrees to send them.', 'phpwarden' ) . ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Review what is sent and turn reports on', 'phpwarden' ) . '</a></p></div>';
	}

	/**
	 * Add the settings page (main site only on multisite).
	 */
	public static function menu() {
		if ( ! PHPWarden_Plugin::should_run() ) {
			return;
		}
		add_options_page(
			__( 'phpwarden', 'phpwarden' ),
			__( 'phpwarden', 'phpwarden' ),
			PHPWarden_Plugin::capability(),
			self::PAGE,
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * "Settings" link on the Plugins screen.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public static function action_links( $links ) {
		if ( PHPWarden_Plugin::should_run() && current_user_can( PHPWarden_Plugin::capability() ) ) {
			array_unshift( $links, '<a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Settings', 'phpwarden' ) . '</a>' );
		}
		return $links;
	}

	/**
	 * URL of the settings page.
	 *
	 * @param string $notice Optional notice key.
	 * @return string
	 */
	private static function page_url( $notice = '' ) {
		$args = array( 'page' => self::PAGE );
		if ( '' !== $notice ) {
			$args['phpwarden_notice'] = $notice;
		}
		return add_query_arg( $args, admin_url( 'options-general.php' ) );
	}

	/**
	 * Abort unless the current user may manage the plugin. Each handler checks its nonce itself.
	 */
	private static function guard() {
		if ( ! PHPWarden_Plugin::should_run() || ! current_user_can( PHPWarden_Plugin::capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'phpwarden' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Save settings.
	 */
	public static function handle_save() {
		self::guard();
		check_admin_referer( 'phpwarden_save' );

		if ( ! PHPWarden_Settings::token_is_constant() ) {
			$token = isset( $_POST['phpwarden_token'] ) ? PHPWarden_Settings::sanitize_token( sanitize_text_field( wp_unslash( $_POST['phpwarden_token'] ) ) ) : '';
			if ( ! empty( $_POST['phpwarden_token_remove'] ) ) {
				PHPWarden_Settings::delete_token();
			} elseif ( '' !== $token ) {
				// An empty field keeps the stored token.
				PHPWarden_Settings::set_token( $token );
			}
		}

		if ( ! PHPWarden_Settings::api_is_constant() ) {
			$api = isset( $_POST['phpwarden_api_base'] ) ? esc_url_raw( wp_unslash( $_POST['phpwarden_api_base'] ), array( 'https', 'http' ) ) : '';
			PHPWarden_Settings::set_api_base( $api );
		}

		PHPWarden_Settings::set_consent( ! empty( $_POST['phpwarden_consent'] ) );
		PHPWarden_Plugin::ensure_schedule();
		wp_safe_redirect( self::page_url( 'saved' ) );
		exit;
	}

	/**
	 * "Send report now".
	 */
	public static function handle_sync() {
		self::guard();
		check_admin_referer( 'phpwarden_sync' );
		$status = PHPWarden_Client::sync( 'manual' );
		wp_safe_redirect( self::page_url( $status['ok'] ? 'synced' : 'sync_failed' ) );
		exit;
	}

	/**
	 * Render the page.
	 */
	public static function render() {
		if ( ! current_user_can( PHPWarden_Plugin::capability() ) ) {
			return;
		}
		$token       = PHPWarden_Settings::get_token();
		$token_const = PHPWarden_Settings::token_is_constant();
		$api_const   = PHPWarden_Settings::api_is_constant();
		$status      = PHPWarden_Settings::get_status();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag.
		$notice     = isset( $_GET['phpwarden_notice'] ) ? sanitize_key( wp_unslash( $_GET['phpwarden_notice'] ) ) : '';
		$const_note = __( 'Set in wp-config.php.', 'phpwarden' );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'phpwarden', 'phpwarden' ); ?></h1>

			<?php if ( 'saved' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.', 'phpwarden' ); ?></p></div>
			<?php elseif ( 'synced' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Report sent.', 'phpwarden' ); ?></p></div>
			<?php elseif ( 'sync_failed' === $notice ) : ?>
				<div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'The report could not be sent. See the status below.', 'phpwarden' ); ?></p></div>
			<?php endif; ?>

			<p><?php esc_html_e( 'This plugin reports the installed WordPress core, plugins, themes and PHP version to your phpwarden dashboard. It is not a firewall or malware scanner.', 'phpwarden' ); ?></p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" autocomplete="off">
				<input type="hidden" name="action" value="phpwarden_save" />
				<?php wp_nonce_field( 'phpwarden_save' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="phpwarden_token"><?php esc_html_e( 'Project token', 'phpwarden' ); ?></label></th>
						<td>
							<?php if ( '' !== $token ) : ?>
								<p><code><?php echo esc_html( PHPWarden_Settings::mask_token( $token ) ); ?></code></p>
							<?php endif; ?>
							<?php if ( $token_const ) : ?>
								<p class="description"><?php echo esc_html( $const_note ); ?> (<code>PHPWARDEN_TOKEN</code>)</p>
							<?php else : ?>
								<input type="password" class="regular-text" id="phpwarden_token" name="phpwarden_token" value="" autocomplete="new-password" spellcheck="false" />
								<p class="description">
									<?php
									echo esc_html(
										'' === $token
											? __( 'Paste the ingest token of your phpwarden project.', 'phpwarden' )
											: __( 'Leave empty to keep the current token.', 'phpwarden' )
									);
									?>
								</p>
								<?php if ( '' !== $token ) : ?>
									<label><input type="checkbox" name="phpwarden_token_remove" value="1" /> <?php esc_html_e( 'Remove the stored token', 'phpwarden' ); ?></label>
								<?php endif; ?>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="phpwarden_api_base"><?php esc_html_e( 'API base URL', 'phpwarden' ); ?></label></th>
						<td>
							<input type="url" class="regular-text code" id="phpwarden_api_base" name="phpwarden_api_base" value="<?php echo esc_attr( PHPWarden_Settings::get_api_base() ); ?>" <?php disabled( $api_const ); ?> />
							<?php if ( $api_const ) : ?>
								<p class="description"><?php echo esc_html( $const_note ); ?> (<code>PHPWARDEN_API</code>)</p>
							<?php else : ?>
								<p class="description"><?php esc_html_e( 'Default: https://app.phpwarden.io. Must use HTTPS (HTTP is allowed only for local development hosts).', 'phpwarden' ); ?></p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Consent', 'phpwarden' ); ?></th>
						<td>
							<label><input type="checkbox" id="phpwarden_consent" name="phpwarden_consent" value="1" <?php checked( PHPWarden_Settings::has_consent() ); ?> /> <?php esc_html_e( 'I agree to send this site\'s software inventory to the phpwarden service.', 'phpwarden' ); ?></label>
							<p class="description">
								<?php
								echo esc_html(
									sprintf(
										/* translators: %s: API base URL. */
										__( 'What is sent: the site address, the WordPress version, the PHP version and server API, the version of this plugin, and for each installed plugin and theme its name, slug, version, whether it is active and any newer version WordPress knows of (for plugins, also the main file path), together with your project token to identify the project. It goes to %s twice a day, about a minute after plugins or themes change, when you press Send report now, and when an administrator runs wp phpwarden activate or wp phpwarden sync. No posts, users, e-mail addresses, passwords or visitor data are sent. Nothing is sent until this box is checked; uncheck it to stop.', 'phpwarden' ),
										PHPWarden_Settings::get_api_base()
									)
								);
								?>
								<a href="https://phpwarden.io/terms" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Terms', 'phpwarden' ); ?></a> &middot;
								<a href="https://phpwarden.io/privacy" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Privacy', 'phpwarden' ); ?></a>
							</p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save settings', 'phpwarden' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Status', 'phpwarden' ); ?></h2>
			<div class="card">
				<?php if ( empty( $status['time'] ) ) : ?>
					<p><?php esc_html_e( 'No report has been sent yet.', 'phpwarden' ); ?></p>
				<?php else : ?>
					<p>
						<strong><?php esc_html_e( 'Last sync:', 'phpwarden' ); ?></strong>
						<?php echo esc_html( self::format_time( $status['time'] ) ); ?>
						<br />
						<strong><?php esc_html_e( 'Result:', 'phpwarden' ); ?></strong>
						<?php
						if ( ! empty( $status['ok'] ) ) {
							esc_html_e( 'OK', 'phpwarden' );
						} else {
							echo esc_html( isset( $status['message'] ) && '' !== $status['message'] ? $status['message'] : __( 'Failed', 'phpwarden' ) );
						}
						?>
						<?php if ( isset( $status['exposed'] ) ) : ?>
							<br />
							<strong><?php esc_html_e( 'Exposed components:', 'phpwarden' ); ?></strong>
							<?php echo esc_html( (string) (int) $status['exposed'] ); ?>
							<br />
							<strong><?php esc_html_e( 'Known exploited (CISA KEV):', 'phpwarden' ); ?></strong>
							<?php echo esc_html( (string) (int) $status['kev'] ); ?>
							<?php if ( empty( $status['ok'] ) && ! empty( $status['last_ok'] ) ) : ?>
								<br /><em>
								<?php
								/* translators: %s: date and time. */
								echo esc_html( sprintf( __( 'Counts are from the last successful report (%s).', 'phpwarden' ), self::format_time( $status['last_ok'] ) ) );
								?>
								</em>
							<?php endif; ?>
						<?php endif; ?>
					</p>
				<?php endif; ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="phpwarden_sync" />
					<?php wp_nonce_field( 'phpwarden_sync' ); ?>
					<?php submit_button( __( 'Send report now', 'phpwarden' ), 'secondary', 'submit', true, ( '' === $token || ! PHPWarden_Settings::has_consent() ) ? array( 'disabled' => 'disabled' ) : array() ); ?>
				</form>
			</div>

		</div>
		<?php
	}

	/**
	 * Format a timestamp in the site's timezone.
	 *
	 * @param int $timestamp Unix time.
	 * @return string
	 */
	private static function format_time( $timestamp ) {
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $timestamp );
	}
}
