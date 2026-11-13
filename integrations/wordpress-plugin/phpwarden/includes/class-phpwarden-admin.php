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
 * Settings → phpwarden.
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
	 * Abort unless the current user may manage the plugin and the nonce is valid.
	 *
	 * @param string $action Nonce action.
	 */
	private static function guard( $action ) {
		if ( ! PHPWarden_Plugin::should_run() || ! current_user_can( PHPWarden_Plugin::capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'phpwarden' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	/**
	 * Save settings.
	 */
	public static function handle_save() {
		self::guard( 'phpwarden_save' );

		if ( ! PHPWarden_Settings::token_is_constant() ) {
			// The token is opaque: it is reduced to bearer-token characters by sanitize_token().
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$token = isset( $_POST['phpwarden_token'] ) ? PHPWarden_Settings::sanitize_token( wp_unslash( $_POST['phpwarden_token'] ) ) : '';
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

		if ( ! PHPWarden_Settings::remote_is_constant() ) {
			PHPWarden_Settings::set_remote_updates( ! empty( $_POST['phpwarden_remote_updates'] ) );
		}

		PHPWarden_Plugin::ensure_schedule();
		wp_safe_redirect( self::page_url( 'saved' ) );
		exit;
	}

	/**
	 * "Send report now".
	 */
	public static function handle_sync() {
		self::guard( 'phpwarden_sync' );
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
		$rem_const   = PHPWarden_Settings::remote_is_constant();
		$remote      = PHPWarden_Settings::remote_updates_enabled();
		$status      = PHPWarden_Settings::get_status();
		$log         = PHPWarden_Settings::get_log();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag.
		$notice      = isset( $_GET['phpwarden_notice'] ) ? sanitize_key( wp_unslash( $_GET['phpwarden_notice'] ) ) : '';
		$const_note  = __( 'Set in wp-config.php.', 'phpwarden' );
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
								<p class="description"><?php esc_html_e( 'Default: https://app.phpwarden.io. Must use HTTPS.', 'phpwarden' ); ?></p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Remote updates', 'phpwarden' ); ?></th>
						<td>
							<label for="phpwarden_remote_updates">
								<input type="checkbox" id="phpwarden_remote_updates" name="phpwarden_remote_updates" value="1" <?php checked( $remote ); ?> <?php disabled( $rem_const ); ?> />
								<?php esc_html_e( 'Allow the phpwarden dashboard to update plugins and themes on this site', 'phpwarden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Off by default. When enabled, the dashboard can ask this site to update an installed plugin or theme to the version WordPress.org offers, or to deactivate a plugin. Nothing else.', 'phpwarden' ); ?>
								<?php if ( $rem_const ) : ?>
									<br /><?php echo esc_html( $const_note ); ?> (<code>PHPWARDEN_REMOTE_UPDATES</code>)
								<?php endif; ?>
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
					<?php submit_button( __( 'Send report now', 'phpwarden' ), 'secondary', 'submit', true, '' === $token ? array( 'disabled' => 'disabled' ) : array() ); ?>
				</form>
			</div>

			<h2><?php esc_html_e( 'Remote command log', 'phpwarden' ); ?></h2>
			<?php if ( empty( $log ) ) : ?>
				<p><?php esc_html_e( 'No remote commands have been run on this site.', 'phpwarden' ); ?></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Time', 'phpwarden' ); ?></th>
							<th><?php esc_html_e( 'Action', 'phpwarden' ); ?></th>
							<th><?php esc_html_e( 'Component', 'phpwarden' ); ?></th>
							<th><?php esc_html_e( 'Result', 'phpwarden' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $log as $entry ) : ?>
							<?php
							if ( ! is_array( $entry ) ) {
								continue;
							}
							$result = ! empty( $entry['ok'] ) ? __( 'OK', 'phpwarden' ) : __( 'Failed', 'phpwarden' );
							if ( ! empty( $entry['from'] ) && ! empty( $entry['to'] ) && $entry['from'] !== $entry['to'] ) {
								$result .= ' (' . $entry['from'] . ' → ' . $entry['to'] . ')';
							}
							if ( ! empty( $entry['message'] ) ) {
								$result .= ': ' . $entry['message'];
							}
							?>
							<tr>
								<td><?php echo esc_html( self::format_time( isset( $entry['time'] ) ? $entry['time'] : 0 ) ); ?></td>
								<td><code><?php echo esc_html( isset( $entry['action'] ) ? $entry['action'] : '' ); ?></code></td>
								<td><?php echo esc_html( isset( $entry['slug'] ) ? $entry['slug'] : '' ); ?></td>
								<td><?php echo esc_html( $result ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
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
