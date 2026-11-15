<?php
function guestbook($conn) {
    $r = mysqli_query($conn, "SELECT name, comment FROM guestbook");
    $out = '';
    while ($row = mysqli_fetch_row($r)) {
        $out .= "<div>" . $row[1] . "</div>";
    }
    return $out;
}
echo guestbook($conn);
$r2 = mysqli_query($conn, "SELECT title FROM notes");
while ($n = mysqli_fetch_assoc($r2)) { echo $n['title']; }
$r3 = mysqli_query($conn, "SELECT name FROM guestbook");
while ($g = mysqli_fetch_assoc($r3)) { echo htmlspecialchars($g['name']); }
$r4 = mysqli_query($conn, "SELECT body FROM posts");
while ($p = mysqli_fetch_assoc($r4)) { echo $p['body']; }
$r5 = mysqli_query($conn, "SELECT name FROM users");
while ($u = mysqli_fetch_assoc($r5)) { echo $u['name']; }
$x = mysqli_fetch_assoc(mysqli_query($conn, "SELECT comment FROM guestbook"));
mysqli_query($conn, "SELECT * FROM log WHERE c = '" . $x['comment'] . "'");
$st = $pdo->query("SELECT * FROM profiles");
foreach ($st->fetchAll() as $pr) {
    echo $pr['bio'];
    echo $pr['age'];
}
