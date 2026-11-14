<?php
// eval($_GET['x']) in a comment must not fire; system($_GET['c']) too.
# include $_GET['p'];
/* unserialize($_COOKIE['x']); */
$s = 'eval($_GET["x"]); system($_POST["c"])';
$d = "this mentions eval( and \$_GET but is just text";
$id = intval($_GET['id']);
mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
$n = (int) $_GET['n'];
$pdo->query("SELECT * FROM t LIMIT $n");
$stmt = $pdo->prepare('SELECT * FROM t WHERE name = ?');
$stmt->execute([$_POST['name']]);
echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
echo 'Hello ' . htmlspecialchars($_GET['name']);
$host = escapeshellarg($_GET['host']);
system("ping -c 1 " . $host);
readfile('/var/files/' . basename($_GET['f']));
$o = unserialize($x, ['allowed_classes' => false]);
$etag = md5($filename);
$checksum = sha1_file($path);
$heredoc = <<<EOT
Example: \$_GET['id'] and eval(\$code)
EOT;
$nowdoc = <<<'EOT'
system($_GET['c']); eval($_POST['x']);
EOT;
echo $nowdoc;
$ok = isset($_GET['debug']) && $_GET['debug'] === '1';
echo $ok;
$page = filter_var($_GET['page'], FILTER_VALIDATE_INT);
include __DIR__ . '/pages/' . $page . '.php';
$password = 'changeme';
$api_key = getenv('API_KEY');
$token = bin2hex(random_bytes(32));
$label = ['password' => 'required|min:8', 'token' => 'csrf_token'];
header('Location: /dashboard');
ini_set('display_errors', 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
setcookie('session_id', $sid, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
$q = $_GET['q'];
$q = 'fixed';
echo $q;
$len = strlen($_GET['x']);
echo $len;
$hash = password_hash($password, PASSWORD_DEFAULT);
$enc = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);
$fn = 'strtoupper';
$fn('x');
$u = $user->getName();
echo $u;
