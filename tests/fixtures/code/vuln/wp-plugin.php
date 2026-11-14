<?php
/* Plugin Name: Vulnerable Demo */
add_action('wp_ajax_nopriv_demo_save', 'demo_save');
function demo_save() {
    update_option('demo_setting', $_POST['value']);
    wp_die();
}
add_action('wp_ajax_demo_delete', 'demo_delete');
function demo_delete() {
    global $wpdb;
    $id = $_POST['id'];
    $wpdb->query("DELETE FROM {$wpdb->prefix}demo WHERE id = $id");   // sql-wpdb
}
function demo_search() {
    global $wpdb;
    $term = get_query_var('s');
    return $wpdb->get_results("SELECT * FROM wp_posts WHERE post_title LIKE '%" . $term . "%'");  // sql-wpdb
}
function demo_go() {
    wp_redirect($_GET['redirect_to']);                       // redirect-wp
    exit;
}
add_action('rest_api_init', function () {
    register_rest_route('demo/v1', '/reset', array(
        'methods' => 'POST',
        'callback' => 'demo_reset',
        'permission_callback' => '__return_true',
    ));
});
function demo_reset($req) {
    delete_option('demo_setting');
}
$resp = wp_remote_get($_GET['feed']);                         // ssrf-wp-remote
$args = array('sslverify' => false);                          // tls-verify-disabled
