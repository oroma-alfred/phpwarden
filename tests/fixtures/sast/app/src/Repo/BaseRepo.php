<?php
namespace App\Repo;

abstract class BaseRepo
{
    public function all() { return []; }
    abstract public function find($id);
}
