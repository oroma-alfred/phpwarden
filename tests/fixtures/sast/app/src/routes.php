<?php
use Illuminate\Support\Facades\Route;
use App\Controller;

Route::get('/u', [Controller::class, 'show']);
Route::post('/m', 'App\Controller@make');
