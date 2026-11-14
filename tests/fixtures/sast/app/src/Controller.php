<?php
namespace App;

use App\Repo\UserRepo;
use Acme\Lib\Client as C;
use function App\Util\clean;

class Controller extends Base
{
    private UserRepo $repo;

    public function show()
    {
        $id = $_GET['id'];
        return $this->repo->find($id);
    }

    public function make()
    {
        $r = new UserRepo(new \App\Db\Db());
        $r->findBy('x');
        $r->finderHello();
        $c = new C();
        $resp = $c->send('q');
        $resp->body();
        /** @var \App\Db\Conn $conn */
        $conn = get_conn();
        $conn->query('x');
        clean($_GET['q']);
        array_map([$this, 'show'], []);
        usort($a, 'strcmp_custom');
        call_user_func('App\Util\clean', 1);
        $f = fn($x) => strtoupper($x);
        $f(1);
        parent::boot();
        $mystery->onlyHereMethod();
        $mystery->find(1);
        acme_helper(1);
        return function () use ($r) { return $r->all(); };
    }

    public function useConn(\App\Db\Conn $c) { return $c->query('y'); }

    /** @param \App\Repo\UserRepo $repo */
    public function docParam($repo) { return $repo->find(2); }

    public function onlyHereMethod() {}
}

class Base
{
    public function boot() {}
}
