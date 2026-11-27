<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

class ApiRateLimitTest extends TestCase
{
    use RefreshDatabase;

    public function test_authenticated_user_is_rate_limited_after_sixty_requests(): void
    {
        $this->freezeTime();

        $user = User::factory()->create();

        $token = $user->createToken('test-token')->plainTextToken;

        $this->withToken($token);

        for ($i = 1; $i <= 60; $i++) {
            $response = $this->getJson('/api/v1/user');

            $response->assertOk();
        }

        $response
            ->assertHeader('X-RateLimit-Limit', '60')
            ->assertHeader('X-RateLimit-Remaining', '0');

        $this->getJson('/api/v1/user')
            ->assertStatus(429)
            ->assertHeader('Retry-After')
            ->assertHeader('X-RateLimit-Remaining', '0')
            ->assertExactJson([
                'success' => false,
                'message' => 'Too many requests.',
                'errors' => null,
            ]);
    }

    public function test_authenticated_users_have_separate_rate_limits(): void
    {
        $this->freezeTime();

        $firstUser = User::factory()->create();
        $secondUser = User::factory()->create();

        Sanctum::actingAs($firstUser);

        for ($i = 1; $i <= 60; $i++) {
            $this->getJson('/api/v1/user')->assertOk();
        }

        $this->getJson('/api/v1/user')
            ->assertStatus(429);

        Sanctum::actingAs($secondUser);

        $this->getJson('/api/v1/user')
            ->assertOk()
            ->assertJsonPath('data.id', $secondUser->id)
            ->assertHeader('X-RateLimit-Remaining', '59');
    }

    public function test_guests_have_separate_rate_limits_based_on_ip(): void
    {
        $this->freezeTime();

        $this->registerGuestRoute();

        $this->withServerVariables([
            'REMOTE_ADDR' => '192.0.2.10',
        ]);

        for ($i = 1; $i <= 60; $i++) {
            $this->getJson('/api/v1/__tests/rate-limit')
                ->assertOk();
        }

        $this->getJson('/api/v1/__tests/rate-limit')
            ->assertStatus(429);

        $this->withServerVariables([
            'REMOTE_ADDR' => '192.0.2.20',
        ]);

        $this->getJson('/api/v1/__tests/rate-limit')
            ->assertOk()
            ->assertHeader('X-RateLimit-Remaining', '59');
    }

    public function test_rate_limit_resets_after_one_minute(): void
    {
        $this->freezeTime();

        $this->registerGuestRoute();

        for ($i = 1; $i <= 60; $i++) {
            $this->getJson('/api/v1/__tests/rate-limit')
                ->assertOk();
        }

        $this->getJson('/api/v1/__tests/rate-limit')
            ->assertStatus(429);

        $this->travel(61)->seconds();

        $this->getJson('/api/v1/__tests/rate-limit')
            ->assertOk()
            ->assertHeader('X-RateLimit-Remaining', '59');

        $this->travelBack();
    }

    private function registerGuestRoute(): void
    {
        Route::middleware('api')
            ->get('/api/v1/__tests/rate-limit', function () {
                return response()->json([
                    'success' => true,
                ]);
            });
    }
}