<?php
namespace App\Db;

class Db implements Conn
{
    public function query(string $sql): array { return mysqli_query($this->link, $sql); }
}
