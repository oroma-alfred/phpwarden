<?php
class Repo {
    private $db;
    public function findByName($name) {
        return $this->db->runSql("SELECT * FROM users WHERE name='" . $name . "'");
    }
}
