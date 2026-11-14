<?php
namespace App\Http\Controllers;

use App\Http\Requests\StorePostRequest;
use App\Models\Comment;
use App\Models\Post;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class PostController extends Controller
{
    public function show($slug)
    {
        return DB::select("select * from posts where slug = '" . $slug . "'");
    }

    public function search(Request $request)
    {
        $q = $request->input('q');
        $rows = DB::table('posts')->whereRaw("title like '%" . $q . "%'")->get();
        $safe = DB::select('select * from posts where title = ?', [$q]);
        return view('search', ['term' => $q, 'count' => count($rows)]);
    }

    public function store(Request $request)
    {
        Comment::create($request->all());
        return Post::create($request->all());
    }

    public function storeSafe(StorePostRequest $request)
    {
        $v = $request->validated();
        return DB::select("select * from posts order by id " . $v['sort']);
    }

    public function go(Request $request)
    {
        return redirect()->away($request->query('next'));
    }

    public function report(Request $request)
    {
        $path = $this->reportPath($request->input('name'));
        return response()->download($path);
    }

    private function reportPath($name)
    {
        return storage_path('reports/' . $name);
    }
}
