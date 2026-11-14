<?php
$repo = new Repo();
$a = $repo->findByName(intval($_GET['n']));
$b = $repo->findByName("bob");
