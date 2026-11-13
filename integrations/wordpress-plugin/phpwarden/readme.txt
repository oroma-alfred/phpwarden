=== phpwarden agent ===
Contributors: phpwarden
Tags: security, vulnerabilities, updates, monitoring, inventory
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Reports your installed plugins, themes, WordPress and PHP versions to your phpwarden dashboard, which ranks vulnerabilities by real-world exploitation.

== Description ==

phpwarden agent connects a WordPress site to a [phpwarden](https://phpwarden.io/) project.

The plugin reports which components are installed. Your phpwarden dashboard matches them against known vulnerabilities and ranks the results by real-world exploitation: first whether a vulnerability is in the CISA Known Exploited Vulnerabilities (KEV) catalog, then by its EPSS score. You see what to patch first instead of a flat list of CVEs.

= What it does =

* Sends an inventory report twice a day, shortly after a plugin or theme is installed, updated, activated, deactivated or deleted, and when you press "Send report now".
* Shows the result of the last report on the settings page: time, status, and the number of exposed components and KEV-listed vulnerabilities.
* Optionally (off by default) lets you update plugins and themes from the phpwarden dashboard.

= What it is not =

phpwarden agent is **not a firewall and not a malware scanner**. It does not block requests, scan files or clean infections. It runs alongside security plugins such as Wordfence or Patchstack and does not replace them.

= Data sent =

Each report contains exactly this, and nothing else:

* The plugin's own agent version (for example `phpwarden-wp/1.0.0`).
* The site address (`home_url()`).
* The PHP version and PHP server API (for example `fpm-fcgi`).
* The WordPress core version.
* For every installed plugin: slug (directory name), main file path relative to the plugins directory, name, version, whether it is active, and the newer version WordPress knows of, if any.
* For every installed theme: slug (directory name), name, version, whether it is active, and the newer version WordPress knows of, if any.
* Whether you have enabled remote updates (true or false).

The project token is sent in the `Authorization` header to identify your project. No user accounts, e-mail addresses, post content, visitor data, file contents, database contents or secrets are sent. The plugin loads no external assets and contains no tracking.

= Remote updates (off by default) =

If, and only if, you tick "Allow the phpwarden dashboard to update plugins and themes on this site" (or set `PHPWARDEN_REMOTE_UPDATES` to `true` in `wp-config.php`), the dashboard can ask the site to do one of three things:

* update an installed plugin,
* update an installed theme,
* deactivate an installed plugin.

Updates are performed by WordPress's own updater and install exactly the version WordPress.org offers for that plugin or theme. The plugin never downloads anything from an address supplied by phpwarden, ignores any other instruction, only acts on plugins and themes that are already installed, runs at most five commands per report, and never deactivates itself. Every command is recorded in a log shown on the settings page. While remote updates are disabled, any command returned by the service is ignored.

= Configuration in wp-config.php =

    define( 'PHPWARDEN_TOKEN', 'your-project-token' );
    define( 'PHPWARDEN_REMOTE_UPDATES', false );
    define( 'PHPWARDEN_API', 'https://app.phpwarden.io' );

Constants take precedence over the settings page and make the corresponding field read-only.

= WP-CLI =

    wp phpwarden activate <token> [--remote-updates]
    wp phpwarden sync
    wp phpwarden status

= Multisite =

The plugin can be network-activated. It reports once for the whole network, from the network's main site, listing all installed plugins and themes. A plugin counts as active when it is network-active or active on the main site; plugins active only on other sites of the network are reported as inactive. Settings are on the main site (Settings → phpwarden) and require a network administrator.

== External services ==

This plugin connects to the phpwarden service at `https://app.phpwarden.io` (or the API base URL you configure). It is required for the plugin to do anything useful: the service matches your inventory against vulnerability data and shows the result in your dashboard.

* **What is sent and when:** the inventory listed under "Data sent" above, together with your project token, twice a day, about a minute after plugin or theme changes, and when you press "Send report now". When remote updates are enabled, the result of each requested update (success or failure, the version before and after, and an error message if any) is also sent.
* **Nothing is sent** until you have entered a project token.
* Service provider: phpwarden. [Terms of service](https://phpwarden.io/terms), [privacy policy](https://phpwarden.io/privacy).

During a remote update WordPress itself contacts WordPress.org to check for and download the update, exactly as it does for an update started from the Plugins screen.

== Installation ==

1. Install and activate the plugin.
2. Create a project in your phpwarden dashboard and copy its token.
3. Go to Settings → phpwarden, paste the token and save.
4. Press "Send report now". The site appears in your dashboard.

== Frequently Asked Questions ==

= Do I need a phpwarden account? =

Yes. The plugin only collects the inventory; matching and ranking happen in your phpwarden dashboard.

= Does this replace Wordfence or Patchstack? =

No. phpwarden agent is not a firewall or malware scanner. It tells you which installed components have vulnerabilities that are being exploited in the wild, so you know what to update first. Keep your firewall or scanner.

= Can phpwarden change my site? =

Not unless you allow it. Remote updates are off by default. When you enable them, phpwarden can only update installed plugins and themes to the version WordPress.org offers, or deactivate a plugin. See "Remote updates" above.

= Where is the token stored? =

In the WordPress options table, or in `wp-config.php` if you define `PHPWARDEN_TOKEN`. The settings page only ever shows its last four characters.

= What happens if the report cannot be sent? =

Nothing on your site changes. The error is shown in the status box and the plugin tries again at the next scheduled report.

= Does it slow down my site? =

No. Reports are sent in the background by WP-Cron, not during visitor page loads, and the plugin adds nothing to the front end.

= What is removed on uninstall? =

All plugin options (token, settings, status, command log) and its scheduled events.

== Changelog ==

= 1.0.0 =
* Initial release: inventory reports, status box, optional remote updates, WP-CLI commands.
