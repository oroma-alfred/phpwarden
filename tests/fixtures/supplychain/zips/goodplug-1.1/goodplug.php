<?php
/* Plugin Name: Good Plug  Version: 1.1 */
$icon = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=';
function goodplug_check() {
    // same licence server as before, new path
    return wp_remote_get('https://api.goodplug.example.net/v2/license', array('timeout' => 10));
}
function goodplug_news() {
    return wp_remote_get('https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=goodplug');
}
add_action('admin_menu', function () { add_options_page('Good', 'Good', 'manage_options', 'good', 'goodplug_page'); });
