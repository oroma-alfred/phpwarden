<?php
namespace App\Db;

interface Conn
{
    public function query(string $sql): array;
}
