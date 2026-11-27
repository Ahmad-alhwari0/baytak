<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class SanctumTokenTest extends TestCase
{
    use RefreshDatabase;

    public function test_access_token_is_stored_as_hash(): void
    {
        $user = User::factory()->create();

        $token = $user->createToken('test-token');

        [$id, $secret] = explode('|', $token->plainTextToken, 2);

        $this->assertDatabaseHas('personal_access_tokens', [
            'id' => $id,
            'tokenable_id' => $user->id,
            'token' => hash('sha256', $secret),
        ]);

        $this->assertDatabaseMissing('personal_access_tokens', [
            'token' => $secret,
        ]);
    }

    public function test_guest_cannot_access_protected_route(): void
    {
        $this->getJson('/api/user')
            ->assertUnauthorized();
    }

    public function test_user_can_access_protected_route_with_valid_token(): void
    {
        $user = User::factory()->create();

        $token = $user->createToken(
            'test-token'
        )->plainTextToken;

        $this->withToken($token)
            ->getJson('/api/user')
            ->assertOk()
            ->assertJsonPath('id', $user->id)
            ->assertJsonMissingPath('password')
            ->assertJsonMissingPath('google_id');
    }

    public function test_revoked_token_is_rejected(): void
    {
        $user = User::factory()->create();

        $token = $user->createToken('test-token');

        $token->accessToken->delete();

        $this->withToken($token->plainTextToken)
            ->getJson('/api/user')
            ->assertUnauthorized();
    }

    public function test_expired_token_is_rejected(): void
    {
        $user = User::factory()->create();

        $token = $user->createToken(
            'test-token',
            ['*'],
            now()->subMinute()
        )->plainTextToken;

        $this->withToken($token)
            ->getJson('/api/user')
            ->assertUnauthorized();
    }

    public function test_soft_deleted_user_cannot_access_protected_route(): void
    {
        $user = User::factory()->create();

        $token = $user->createToken(
            'test-token'
        )->plainTextToken;

        $user->delete();

        $this->withToken($token)
            ->getJson('/api/user')
            ->assertUnauthorized();
    }
}