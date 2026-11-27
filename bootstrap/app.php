<?php

use App\Support\ApiResponse;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->redirectGuestsTo(
            fn (Request $request) => $request->is('api', 'api/*')
                ? null
                : route('login')
        );
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request, \Throwable $e): bool =>
                $request->is('api', 'api/*') || $request->expectsJson()
        );

        $exceptions->render(function (\Throwable $e, Request $request) {
            if (!$request->is('api', 'api/*')) {
                return null;
            }

            if ($e instanceof HttpResponseException) {
                return null;
            }

            if ($e instanceof ValidationException) {
                return ApiResponse::error(
                    message: 'Validation failed.',
                    status: $e->status,
                    errors: $e->errors()
                );
            }

            if ($e instanceof AuthenticationException) {
                return ApiResponse::error(
                    message: 'Unauthenticated.',
                    status: 401
                );
            }

            if ($e instanceof HttpExceptionInterface) {
                $status = $e->getStatusCode();

                $message = match ($status) {
                    400 => 'Bad request.',
                    401 => 'Unauthenticated.',
                    403 => 'Forbidden.',
                    404 => 'Not found.',
                    405 => 'Method not allowed.',
                    409 => 'Conflict.',
                    422 => 'Validation failed.',
                    429 => 'Too many requests.',
                    500 => 'Internal server error.',
                    default => Response::$statusTexts[$status]
                        ?? 'Request failed.',
                };

                return ApiResponse::error(
                    message: $message,
                    status: $status
                )->withHeaders($e->getHeaders());
            }

            return ApiResponse::error(
                message: 'Internal server error.',
                status: 500
            );
        });
    })->create();