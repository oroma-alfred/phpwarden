<?php
use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

Route::get('/posts/{slug}', [PostController::class, 'show']);
Route::get('/search', [PostController::class, 'search']);
Route::post('/posts', [PostController::class, 'store']);
Route::post('/posts/safe', [PostController::class, 'storeSafe']);
Route::get('/go', [PostController::class, 'go']);
Route::get('/report', [PostController::class, 'report']);
