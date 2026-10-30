<?php

use think\facade\Route;

$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';

// 前台（需要登录；系统只验证登录，产品归属在控制器里自己校验）
Route::group('console/v1', function () {
    // 免密登录 CDN 控制台：返回一次性登录链接，前端新窗口打开
    Route::post('cdnca/host/:id/sso', "\\server\\cdnca\\controller\\home\\HostController@sso");
})->allowCrossDomain([
    'Access-Control-Allow-Origin' => $origin,
    'Access-Control-Allow-Credentials' => 'true',
    'Access-Control-Max-Age' => 600,
])->middleware(\app\http\middleware\CheckHome::class)
    ->middleware(\app\http\middleware\ParamFilter::class)
    ->middleware(\app\http\middleware\RejectRepeatRequest::class);

// 后台（需要管理员登录）
Route::group(DIR_ADMIN . '/v1', function () {
    // 保存商品的 CDN 套餐与周期售价
    Route::post('cdnca/product/:product_id', "\\server\\cdnca\\controller\\admin\\ProductController@save");
})->allowCrossDomain([
    'Access-Control-Allow-Origin' => $origin,
    'Access-Control-Allow-Credentials' => 'true',
    'Access-Control-Max-Age' => 600,
])->middleware(\app\http\middleware\CheckAdmin::class)
    ->middleware(\app\http\middleware\ParamFilter::class);
