<?php
function strcmp_custom($a, $b) { return strcmp($a, $b); }
function my_init() {}
add_action('init', 'my_init');
