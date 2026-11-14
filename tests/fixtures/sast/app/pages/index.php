<?php
define('ROOT', '../');
switch ($_GET['level']) {
    case 'low':
        $file = 'low.php';
        break;
    default:
        $file = 'high.php';
}
require_once ROOT . "pages/source/{$file}";
include __DIR__ . '/source/' . $_GET['x'] . '.php';
require dirname(__FILE__) . '/../src/legacy.php';
include $_GET['anything'];
