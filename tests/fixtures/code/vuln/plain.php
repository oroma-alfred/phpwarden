<?php
// Plain PHP vulnerable samples. One per category.
$id = $_GET['id'];
$q = "SELECT * FROM users WHERE id = $id";
mysqli_query($conn, $q);                                   // sql-mysqli-query (via var + interpolation)
$pdo->query("SELECT * FROM t WHERE name = '" . $_POST['name'] . "'");  // sql-db-query
eval($_REQUEST['code']);                                   // eval-tainted
eval(base64_decode('ZWNobyAxOw=='));                       // eval-encoded-payload
$cmd = $_GET['host'];
system("ping -c 1 " . $cmd);                               // cmd-system
$out = `ls {$_GET['dir']}`;                                // cmd-backtick
include $_GET['page'] . '.php';                            // include-tainted
$data = unserialize($_COOKIE['prefs']);                    // unserialize-tainted
echo "Hello " . $_GET['name'];                             // xss-echo
header('Location: ' . $_GET['next']);                      // redirect-header
$file = $_GET['f'];
readfile('/var/www/files/' . $file);                       // path-readfile
file_put_contents($_POST['path'], 'x');                    // path-write
unlink($_GET['del']);                                      // path-delete
move_uploaded_file($_FILES['up']['tmp_name'], 'uploads/' . $_FILES['up']['name']);  // path-move-upload
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_GET['url']);               // ssrf-curl
$page = file_get_contents('http://' . $_GET['host'] . '/status');  // ssrf-file-get-contents
$fn = $_GET['callback'];
$fn();                                                     // variable-function-tainted
call_user_func($_POST['action']);                          // call-user-func-tainted
extract($_POST);                                           // extract-superglobal
parse_str($_SERVER['QUERY_STRING']);                       // parse-str-one-arg
$hash = md5($password);                                    // weak-hash-password
$token = md5(mt_rand());                                   // weak-random-secret
$enc = openssl_encrypt($data, 'aes-128-ecb', $key);        // openssl-ecb
ini_set('display_errors', 1);                              // display-errors-on
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);           // tls-verify-disabled
$db_password = 'Sup3rS3cr3t!x';                            // hardcoded-secret
$x = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);  // xxe-noent
libxml_disable_entity_loader(false);                       // xxe-entity-loader
setcookie('session_token', $sid);                          // cookie-insecure
$name = $_GET['v'];
$$name = 1;                                                // variable-variable-tainted
$cb = create_function('$a', 'return $a;');                 // create-function
$r = preg_replace('/(.*)/e', 'strtoupper("\\1")', $in);    // preg-replace-e
$obj = unserialize($cached);                               // unserialize-no-allowed-classes
shell_exec('convert ' . $_GET['img']);                     // cmd-shell-exec
$ua = $_SERVER['HTTP_USER_AGENT'];
$pdo->exec("INSERT INTO log VALUES ('$ua')");              // sql-db-query via $_SERVER HTTP_*
$body = file_get_contents('php://input');
$o = unserialize($body);                                   // unserialize-tainted via php://input
