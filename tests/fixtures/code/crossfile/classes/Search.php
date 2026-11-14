<?php
class Search {
    private $q;
    private $c;
    public function readInput() {
        $this->q = $_POST['q'];
    }
    public function execute() {
        return mysqli_query($this->c, "SELECT * FROM posts WHERE title='$this->q'");
    }
}
