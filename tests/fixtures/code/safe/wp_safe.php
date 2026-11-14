<?php
add_action('wp_ajax_nopriv_safe_save', 'safe_save');
function safe_save() {
    check_ajax_referer('safe_save');
    if (!current_user_can('manage_options')) { wp_die(); }
    update_option('safe_setting', sanitize_text_field($_POST['value']));
}
add_action('wp_ajax_safe_read', 'safe_read');
function safe_read() {
    global $wpdb;
    $id = absint($_POST['id']);
    $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->prefix}demo WHERE id = %d", $_POST['id']));
    echo esc_html($_GET['msg']);
    echo esc_attr( $_POST['x'] );
    wp_safe_redirect($_GET['redirect_to']);
    $s = esc_sql($_GET['s']);
    $wpdb->query("SELECT * FROM t WHERE s = '$s'");
    wp_send_json($rows);
}
register_rest_route('safe/v1', '/items', array(
    'methods' => 'GET',
    'callback' => 'safe_items',
    'permission_callback' => '__return_true',
));
function safe_items() { return get_option('safe_setting'); }
