<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthCandidate;
use App\Http\Controllers\Auth\AuthController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('register', [AuthCandidate::class, 'register'])->name('register');
Route::post('login', [AuthCandidate::class, 'login'])->name('login');
Route::post('login_facebook', [AuthCandidate::class, 'loginFacebook'])->name('login_facebook');
Route::get('test', [AuthCandidate::class, 'test'])->name('test')->middleware('checklogin');

