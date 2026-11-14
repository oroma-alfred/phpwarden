<?php
$repo = new Repo();
$rows = $repo->findByName($_GET['n']);
