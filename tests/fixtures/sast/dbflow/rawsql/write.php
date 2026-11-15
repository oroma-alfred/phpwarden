<?php
$name = $_POST['name'];
$msg = mysqli_real_escape_string($conn, $_POST['msg']);
$q = "INSERT INTO guestbook ( comment, name ) VALUES ( '$msg', '$name' );";
mysqli_query($conn, $q);
$clean = htmlspecialchars($_POST['title']);
mysqli_query($conn, "INSERT INTO notes (title) VALUES ('" . mysqli_real_escape_string($conn, $clean) . "')");
$t = $_GET['t'];
mysqli_query($conn, "INSERT INTO $t (body) VALUES ('" . mysqli_real_escape_string($conn, $_POST['b']) . "')");
$pdo->exec("UPDATE profiles SET bio = '" . addslashes($_POST['bio']) . "', age = 3 WHERE id = 1");
