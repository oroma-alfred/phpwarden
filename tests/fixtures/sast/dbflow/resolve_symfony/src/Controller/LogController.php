<?php
namespace App\Controller;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
class LogController extends AbstractController {
    public function add($conn) {
        $t = $this->getParameter('app.log_table');
        mysqli_query($conn, "INSERT INTO " . $t . " (entry) VALUES ('" . $_POST['entry'] . "')");
        mysqli_query($conn, "INSERT INTO " . $this->getParameter('app.other') . " (o) VALUES ('" . $_POST['o'] . "')");
    }
    public function list($conn) {
        $r = mysqli_query($conn, "SELECT entry FROM app_log");
        while ($row = mysqli_fetch_assoc($r)) { echo $row['entry']; }
        $r2 = mysqli_query($conn, "SELECT o FROM other_log");
        while ($row2 = mysqli_fetch_assoc($r2)) { echo $row2['o']; }
    }
}
