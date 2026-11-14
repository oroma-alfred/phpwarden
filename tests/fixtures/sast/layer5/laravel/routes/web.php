<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PostController;
Route::post('/posts', [PostController::class, 'store']);
Route::get('/posts', [PostController::class, 'index']);
Route::middleware('auth')->group(function () {
    Route::put('/posts/{post}', [PostController::class, 'update']);
    Route::delete('/posts/{post}', [PostController::class, 'destroy']);
    Route::patch('/posts/{post}/publish', [PostController::class, 'publish']);
});
Route::post('/webhook/stripe', [PostController::class, 'webhook']);
