<?php
$items = find_items(array('orderby' => $_GET['orderby'], 'search' => $_GET['q']));
$raw = find_raw(array('raw' => $_GET['id'], 'other' => 1));
$data = fetch_remote($_GET['p']);
$any = file_get_contents($_GET['url']);
