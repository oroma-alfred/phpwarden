<?php
namespace App\Http\Controllers;
use App\Models\Post;
use Illuminate\Http\Request;
class PostController extends Controller
{
    public function index() { return Post::all(); }
    public function store(Request $request) { return Post::create($request->only(['title'])); }
    public function update(Request $request, Post $post) { $post->update($request->only(['title'])); return $post; }
    public function destroy(Post $post) { $this->authorize('delete', $post); $post->delete(); }
    public function publish(Post $post) { abort_if($post->user_id !== auth()->id(), 403); $post->update(['published' => true]); }
    public function webhook(Request $request) { Post::create(['title' => 'x']); }
}
