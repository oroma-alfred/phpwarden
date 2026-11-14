<?php
namespace App\Repo;

use App\Db\Db;

class UserRepo extends BaseRepo
{
    use Finder, Greeter {
        Greeter::hello insteadof Finder;
        Finder::hello as finderHello;
    }

    public function __construct(private Db $db) {}

    public function find($id)
    {
        return $this->db->query("SELECT * FROM users WHERE id = $id");
    }
}
