<?php
/**
 * Plugin Name:       phpwarden
 * Plugin URI:        https://phpwarden.io/docs#wp-plugin
 * Description:       Reports the installed WordPress core, plugins, themes and PHP version to your phpwarden dashboard, which ranks vulnerabilities by real-world exploitation (CISA KEV, then EPSS). Optional, off-by-default remote updates.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            phpwarden
 * Author URI:        https://phpwarden.io/about
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       phpwarden
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'PHPWARDEN_VERSION', '1.0.0' );
define( 'PHPWARDEN_PLUGIN_FILE', __FILE__ );

require_once __DIR__ . '/includes/class-phpwarden-settings.php';
require_once __DIR__ . '/includes/class-phpwarden-inventory.php';
require_once __DIR__ . '/includes/class-phpwarden-commands.php';
require_once __DIR__ . '/includes/class-phpwarden-client.php';
require_once __DIR__ . '/includes/class-phpwarden-plugin.php';

if ( is_admin() ) {
	require_once __DIR__ . '/includes/class-phpwarden-admin.php';
	PHPWarden_Admin::init();
}

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once __DIR__ . '/includes/class-phpwarden-cli.php';
	WP_CLI::add_command( 'phpwarden', 'PHPWarden_CLI' );
}

register_activation_hook( __FILE__, array( 'PHPWarden_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'PHPWarden_Plugin', 'deactivate' ) );

PHPWarden_Plugin::init();
