<?php
function show_it($v) { echo $v; }
function wrap($v) { return "<b>" . $v . "</b>"; }
$b = array_map(function ($x) { return trim($x); }, $_GET['b']);
echo $b[0];
call_user_func('show_it', $_GET['c']);
$r = preg_replace_callback('/x/', function ($m) { return strtoupper($m[0]); }, $_GET['d']);
echo $r;
$f = 'show_it';
$f($_GET['e']);
$g = show_it(...);
$g($_GET['g']);
add_filter('my_title', function ($t) { echo $t; return $t; });
apply_filters('my_title', $_GET['h']);
usort($_GET['u'], function ($a, $b) { echo $a; return 0; });
$w = array_map(fn($x) => wrap($x), $_GET['w']);
echo $w[0];
array_map('show_it', ['a', 'b']);
call_user_func('show_it', htmlspecialchars($_GET['c2']));
$b2 = array_map(function ($x) { return (int) $x; }, $_GET['b2']);
echo $b2[0];
apply_filters('my_title', 'static');
$h = 'show_it';
$h('literal');
