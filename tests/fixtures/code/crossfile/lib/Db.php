<?php
class Db {
    private $conn;
    public function runSql($sql) {
        return $this->conn->query($sql);
    }
}
