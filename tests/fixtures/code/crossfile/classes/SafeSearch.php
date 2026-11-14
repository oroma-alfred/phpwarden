<?php
class SafeSearch {
    private $limit;
    private $c;
    public function readLimit() {
        $this->limit = (int) $_POST['limit'];
    }
    public function list() {
        return mysqli_query($this->c, "SELECT * FROM posts LIMIT " . $this->limit);
    }
}
