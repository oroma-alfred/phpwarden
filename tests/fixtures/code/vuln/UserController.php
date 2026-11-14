<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function index(Request $request)
    {
        $sort = $request->input('sort');
        return DB::table('users')->orderByRaw($sort . ' desc')->get();   // sql-laravel-raw
    }

    public function search(Request $request)
    {
        $name = $request->query('name');
        return DB::select("select * from users where name = '$name'");     // sql-laravel-db
    }

    public function show()
    {
        $id = request('id');
        return DB::table('users')->whereRaw("id = " . $id)->first();     // sql-laravel-raw
    }

    public function go(Request $request)
    {
        return redirect($request->get('url'));                         // redirect-laravel
    }

    public function sym(Request $request)
    {
        $q = $request->query->get('q');
        $em->createQuery("SELECT u FROM User u WHERE u.name = '" . $q . "'");  // sql-doctrine
    }

    private $apiKey = 'fixture-not-a-real-key-9f8A7b6C';                       // hardcoded-secret
}
