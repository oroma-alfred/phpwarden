<?php
namespace App\Http\Controllers;
use App\Models\Post;
use App\Models\Comment;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class PostController {
    public function store(Request $request) {
        Post::create(['title' => $request->input('title'), 'body' => e($request->input('body'))]);
        $c = new Comment();
        $c->text = $request->input('text');
        $c->save();
        DB::table('tags')->insert(['label' => $request->input('label')]);
    }
    public function show($id) {
        $p = Post::find($id);
        echo $p->title;
        echo $p->body;
        echo $p->summary;
        $c = Comment::where('id', $id)->first();
        echo $c->text;
        echo e($c->text);
        echo DB::table('tags')->where('id', $id)->value('label');
        $t = DB::table('tags')->first();
        echo $t->label;
    }
}
