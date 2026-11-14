<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class SafeController extends Controller
{
    public function index(Request $request)
    {
        $users = DB::select('select * from users where name = ?', [$request->input('name')]);
        $rows = DB::table('users')->whereRaw('id = ?', [$request->input('id')])->get();
        $n = (int) $request->input('n');
        DB::table('users')->orderByRaw('created_at desc')->limit($n)->get();
        return redirect()->route('home');
    }
    protected $fillable = ['name'];
    private $password_field = 'password';
}
