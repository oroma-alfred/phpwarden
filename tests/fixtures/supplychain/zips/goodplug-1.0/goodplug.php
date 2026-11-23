<?php
/* Plugin Name: Good Plug  Version: 1.0 */
$icon = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=';
function goodplug_check() {
    return wp_remote_get('https://api.goodplug.example.net/v1/license');
}
add_action('admin_menu', function () { add_options_page('Good', 'Good', 'manage_options', 'good', 'goodplug_page'); });
