<?php
/*
Plugin Name: Fixture Plugin
*/
add_action('wp_ajax_nopriv_fx_save', 'fx_save');
add_action('wp_ajax_fx_safe_save', 'fx_safe_save');
add_action('rest_api_init', function () {
    register_rest_route('fx/v1', '/note', array(
        'methods' => 'POST',
        'callback' => 'fx_rest_note',
        'permission_callback' => '__return_true',
    ));
});

function fx_save() {
    global $wpdb;
    $id = $_POST['id'];
    $wpdb->query("DELETE FROM {$wpdb->prefix}notes WHERE id = " . $id);
    update_option($_POST['key'], 'x');
    wp_send_json_success();
}

function fx_safe_save() {
    check_ajax_referer('fx');
    if (!current_user_can('manage_options')) {
        wp_die();
    }
    global $wpdb;
    $id = absint($_POST['id']);
    $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}notes WHERE id = %d", $_POST['id']));
    $wpdb->query("DELETE FROM {$wpdb->prefix}notes WHERE id = " . $id);
    update_option('fx_last', sanitize_text_field(wp_unslash($_POST['v'])));
    echo esc_html($_POST['v']);
    wp_send_json_success();
}

function fx_rest_note(WP_REST_Request $request) {
    $note = $request->get_param('note');
    update_option('fx_note', $note);
    echo $note;
    return array('ok' => true);
}

function fx_page() {
    $tab = get_query_var('tab');
    echo '<div>' . $tab . '</div>';
    $mode = $_GET['mode'];
    if (!in_array($mode, array('list', 'grid'), true)) {
        return;
    }
    echo $mode;
    $data = maybe_unserialize(wp_unslash($_COOKIE['fx']));
    wp_redirect($_GET['to']);
}
