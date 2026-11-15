<?php
function save_ticket() {
    global $wpdb;
    $wpdb->insert($wpdb->prefix . 'tickets', array('subject' => $_POST['subject'], 'note' => sanitize_text_field($_POST['note'])));
}
function list_tickets() {
    global $wpdb;
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}tickets");
    foreach ($rows as $r) {
        echo $r->subject;
        echo $r->note;
        echo esc_html($r->subject);
    }
    $tbl = $_GET['tbl'];
    $wpdb->insert($tbl, array('x' => $_POST['x']));
    $o = $wpdb->get_row("SELECT x FROM {$wpdb->prefix}other");
    echo $o->x;
}
