<?php

namespace Tests\Feature;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use RuntimeException;
use Tests\TestCase;

class ApiExceptionTest extends TestCase
{
    public function test_guest_receives_standard_json_without_accept_header(): void
    {
        $response = $this->get('/api/v1/user');

        $response
            ->assertStatus(401)
            ->assertHeader('Content-Type', 'application/json')
            ->assertHeaderMissing('Location')
            ->assertExactJson([
                'success' => false,
                'message' => 'Unauthenticated.',
                'errors' => null,
            ]);
    }

    public function test_validation_errors_use_standard_response(): void
    {
        Route::post('/api/v1/__tests/validation', function (Request $request) {
            $request->validate([
                'email' => ['required', 'email'],
            ]);

            return response()->noContent();
        });

        $response = $this->postJson('/api/v1/__tests/validation', []);

        $response
            ->assertStatus(422)
            ->assertJsonPath('success', false)
            ->assertJsonPath('message', 'Validation failed.')
            ->assertJsonValidationErrors(['email']);
    }

    public function test_unknown_api_route_returns_standard_not_found_response(): void
    {
        $response = $this->get('/api/v1/__tests/missing-route');

        $response
            ->assertStatus(404)
            ->assertHeader('Content-Type', 'application/json')
            ->assertExactJson([
                'success' => false,
                'message' => 'Not found.',
                'errors' => null,
            ]);
    }

    public function test_authorization_exception_returns_standard_forbidden_response(): void
    {
        Route::get('/api/v1/__tests/forbidden', function () {
            throw new AuthorizationException('Internal policy details.');
        });

        $response = $this->getJson('/api/v1/__tests/forbidden');

        $response
            ->assertStatus(403)
            ->assertExactJson([
                'success' => false,
                'message' => 'Forbidden.',
                'errors' => null,
            ]);
    }

    public function test_method_not_allowed_preserves_allow_header(): void
    {
        Route::get('/api/v1/__tests/get-only', function () {
            return response()->noContent();
        });

        $response = $this->postJson('/api/v1/__tests/get-only');

        $response
            ->assertStatus(405)
            ->assertHeader('Allow')
            ->assertExactJson([
                'success' => false,
                'message' => 'Method not allowed.',
                'errors' => null,
            ]);

        $allowedMethods = array_map(
            'trim',
            explode(',', (string) $response->headers->get('Allow'))
        );

        $this->assertEqualsCanonicalizing(
            ['GET', 'HEAD'],
            $allowedMethods
        );
    }

    public function test_rate_limit_error_preserves_retry_after_header(): void
    {
        Route::get('/api/v1/__tests/rate-limited', function () {
            abort(429, 'Internal rate-limit details.', [
                'Retry-After' => '60',
            ]);
        });

        $response = $this->getJson('/api/v1/__tests/rate-limited');

        $response
            ->assertStatus(429)
            ->assertHeader('Retry-After', '60')
            ->assertExactJson([
                'success' => false,
                'message' => 'Too many requests.',
                'errors' => null,
            ]);
    }

    public function test_unexpected_exception_hides_details_even_when_debug_enabled(): void
    {
        config(['app.debug' => true]);

        Route::get('/api/v1/__tests/server-error', function () {
            throw new RuntimeException('INTERNAL_TEST_DETAILS_DO_NOT_EXPOSE');
        });

        $response = $this->getJson('/api/v1/__tests/server-error');

        $response
            ->assertStatus(500)
            ->assertExactJson([
                'success' => false,
                'message' => 'Internal server error.',
                'errors' => null,
            ]);
    }

    public function test_web_errors_still_return_html(): void
    {
        config(['app.debug' => false]);

        $response = $this->get('/__tests/missing-web-page', [
            'Accept' => 'text/html',
        ]);

        $response->assertStatus(404);

        $this->assertStringContainsString(
            'text/html',
            (string) $response->headers->get('Content-Type')
        );
    }
}