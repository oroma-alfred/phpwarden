<?php
function find_items($args) {
    $args = array_merge(array('orderby' => 'name', 'search' => ''), $args);
    global $db;
    $order = strtolower($args['orderby']);
    switch ($order) {
        case 'date': $col = 'created'; break;
        default: $col = 'name';
    }
    $like = $db->esc_like($args['search']);
    return $db->get_results("SELECT * FROM items WHERE t LIKE '%" . esc_sql($like) . "%' ORDER BY $col");
}
function find_raw($args) {
    global $wpdb;
    return $wpdb->get_results("SELECT * FROM items WHERE t = " . $args['raw']);
}
function fetch_remote($path) {
    $base = 'https://api.example.com/v1/';
    return file_get_contents($base . $path);
}
