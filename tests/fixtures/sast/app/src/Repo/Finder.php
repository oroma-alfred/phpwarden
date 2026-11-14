<?php
namespace App\Repo;

trait Finder
{
    public function findBy($k) { return $k; }
    public function hello() { return 'finder'; }
}
