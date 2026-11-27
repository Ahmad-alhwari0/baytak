<?php

use App\Support\ApiResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function () {
    Route::get('/user', function (Request $request) {
        return ApiResponse::success(
            data: $request->user(),
            message: 'User retrieved successfully.'
        );
    })->middleware('auth:sanctum');
});