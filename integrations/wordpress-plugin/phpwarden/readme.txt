=== phpwarden ===
Contributors: phpwarden
Tags: security, vulnerabilities, monitoring, inventory, cve
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.2.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Reports installed plugins, themes, WordPress and PHP versions to phpwarden, which ranks vulnerabilities by real-world exploitation.

== Description ==

phpwarden connects a WordPress site to a [phpwarden](https://phpwarden.io/) project.

The plugin reports which components are installed. Your phpwarden dashboard matches them against known vulnerabilities and ranks the results by real-world exploitation: first whether a vulnerability is in the CISA Known Exploited Vulnerabilities (KEV) catalog, then by its EPSS score. You see what to patch first instead of a flat list of CVEs.

= What it does =

* Sends an inventory report twice a day, shortly after a plugin or theme is installed, updated, activated, deactivated or deleted, and when you press "Send report now".
* Shows the result of the last report on the settings page: time, status, and the number of exposed components and KEV-listed vulnerabilities.
* Report only: it never makes changes to your site on behalf of the service, and ignores any instruction in the service's response.

= What it is not =

This plugin is **not a firewall and not a malware scanner**. It does not block requests, scan files or clean infections. It runs alongside security plugins such as Wordfence or Patchstack and does not replace them.

= Data sent =

Each report contains exactly this, and nothing else:

* The plugin's own agent version (for example `phpwarden-wp/1.2.0`).
* The site address (`home_url()`).
* The PHP version and PHP server API (for example `fpm-fcgi`).
* The WordPress core version.
* For every installed plugin: slug (directory name, or for a single-file plugin its file name without .php), main file path relative to the plugins directory, name, version, whether it is active, and the newer version WordPress knows of, if any.
* For every installed theme: slug (directory name), name, version, whether it is active, and the newer version WordPress knows of, if any.
* `remote_updates: false`, a fixed value telling the service that this plugin never accepts actions from it.

The project token is sent in the `Authorization` header to identify your project. No user accounts, e-mail addresses, post content, visitor data, file contents, database contents or secrets are sent. The plugin loads no external assets and contains no tracking.

= Configuration in wp-config.php =

    define( 'PHPWARDEN_TOKEN', 'your-project-token' );
    define( 'PHPWARDEN_API', 'https://app.phpwarden.io' );

Constants take precedence over the settings page and make the corresponding field read-only.

= WP-CLI =

    wp phpwarden activate <token> --consent   # stores the token, records consent, sends a report
    wp phpwarden sync                         # sends a report now (only if consent is given)
    wp phpwarden status
    wp phpwarden disable                      # withdraws consent; nothing more is sent

= Multisite =

The plugin can be network-activated. It reports once for the whole network, from the network's main site, listing all installed plugins and themes. A plugin counts as active when it is network-active or active on the main site; plugins active only on other sites of the network are reported as inactive. Settings are on the main site (Settings > phpwarden) and require a network administrator.

== External services ==

This plugin connects to the phpwarden service at `https://app.phpwarden.io` (or the API base URL you configure). It is required for the plugin to do anything useful: the service matches your inventory against vulnerability data and shows the result in your dashboard.

* **Consent first:** nothing is sent until an administrator checks "I agree to send this site's software inventory to the phpwarden service" on Settings > phpwarden, or runs `wp phpwarden activate <token> --consent`. The box is unchecked by default. Defining `PHPWARDEN_TOKEN` in wp-config.php does not give consent on its own. Unchecking the box (or `wp phpwarden disable`) stops all reports.
* **What is sent and when:** the inventory listed under "Data sent" above, together with your project token, twice a day, about a minute after plugin or theme changes, when you press "Send report now", and when you run `wp phpwarden activate` or `wp phpwarden sync`.
* **Nothing is sent** without both consent and a project token.
* **WordPress's own update check:** to report which plugins and themes have updates waiting, the plugin reads WordPress's cached update list. If that list is missing or more than 12 hours old, it first asks WordPress core to refresh it, which is the same request to api.wordpress.org that WordPress makes on its own schedule. This happens only when a report is being sent, so never without consent, and it is skipped when the site has turned off WordPress's update checks.
* Service provider: phpwarden. [Terms of service](https://phpwarden.io/terms), [privacy policy](https://phpwarden.io/privacy).

== Installation ==

1. Install and activate the plugin.
2. Create a project in your phpwarden dashboard and copy its token.
3. Go to Settings > phpwarden, paste the token, check the consent box (it explains exactly what is sent) and save.
4. Press "Send report now". The site appears in your dashboard.

== Frequently Asked Questions ==

= Do I need a phpwarden account? =

Yes. The plugin only collects the inventory; matching and ranking happen in your phpwarden dashboard.

= Does this replace Wordfence or Patchstack? =

No. This plugin is not a firewall or malware scanner. It tells you which installed components have vulnerabilities that are being exploited in the wild, so you know what to update first. Keep your firewall or scanner.

= Can phpwarden change my site? =

No. The plugin only sends the report described above. It never installs, updates, activates or deactivates anything, never creates or changes user accounts, and never runs instructions from the service. You make every change yourself, in WordPress.

= Where is the token stored? =

In the WordPress options table, or in `wp-config.php` if you define `PHPWARDEN_TOKEN`. The settings page only ever shows its last four characters.

= What happens if the report cannot be sent? =

Nothing on your site changes. The error is shown in the status box and the plugin tries again at the next scheduled report.

= Does it slow down my site? =

No. Reports are sent in the background by WP-Cron, not during visitor page loads, and the plugin adds nothing to the front end.

= What is removed on uninstall? =

All plugin options (token, settings, status) and its scheduled events.

== Changelog ==

= 1.2.0 =
* Nothing is sent until an administrator explicitly agrees: a new, unchecked consent box on the settings page (or `wp phpwarden activate <token> --consent`). This includes sites with the token set in wp-config.php.
* The settings page says what is sent and where, with links to the terms and privacy policy.
* New `wp phpwarden disable` to withdraw consent; `wp phpwarden status` shows the consent state.
* Readme documents every field sent and every action that sends a report.
* A notice on the Plugins screen when reports are off because consent has not been given yet (for example after upgrading from 1.1.0).
* The WordPress update-list refresh is skipped on sites that have turned off WordPress's update checks.

= 1.1.0 =
* Report only. Removed the optional remote updates: the plugin never acts on the site for the service.

= 1.0.0 =
* Initial release: inventory reports, status box, WP-CLI commands (it also had optional remote updates, removed in 1.1.0).
