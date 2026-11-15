<?php
define('ACME_TICKETS', 'acme_tickets');
const ACME_NOTES = 'acme_notes';
if ($x) { define('ACME_FLIP', 'flip_a'); } else { define('ACME_FLIP', 'flip_b'); }
class Acme_Store {
    const TABLE = 'acme_orders';
    const FULL = self::TABLE . '_log';
    public function save() {
        global $wpdb;
        $wpdb->insert($wpdb->prefix . ACME_TICKETS, array('subject' => $_POST['subject']));
        $wpdb->insert($wpdb->prefix . self::TABLE, array('who' => $_POST['who']));
        $wpdb->query("INSERT INTO {$wpdb->prefix}" . ACME_NOTES . " (body) VALUES ('" . $_POST['body'] . "')");
        $t = $wpdb->prefix . self::FULL;
        $wpdb->insert($t, array('line' => $_POST['line']));
        $wpdb->insert($wpdb->options, array('option_value' => $_POST['ov']));
        $wpdb->insert(acme_table_name(), array('m' => $_POST['m']));
        $wpdb->insert($wpdb->prefix . ACME_FLIP, array('f' => $_POST['f']));
        $wpdb->insert($wpdb->prefix . $_GET['tbl'], array('g' => $_POST['g']));
    }
    public function show() {
        global $wpdb;
        $r = $wpdb->get_row("SELECT * FROM wp_acme_tickets");
        echo $r->subject;
        $o = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}acme_orders");
        echo $o->who;
        $n = $wpdb->get_row("SELECT body FROM " . $wpdb->prefix . "acme_notes");
        echo $n->body;
        $l = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}acme_orders_log");
        echo $l->line;
        $op = $wpdb->get_row("SELECT * FROM $wpdb->options WHERE option_name = 'x'");
        echo $op->option_value;
        $m = $wpdb->get_row("SELECT * FROM wp_mystery");
        echo $m->m;
        $fa = $wpdb->get_row("SELECT * FROM wp_flip_a");
        echo $fa->f;
        $gg = $wpdb->get_row("SELECT * FROM wp_anything");
        echo $gg->g;
    }
}
