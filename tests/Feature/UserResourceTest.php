<?php

namespace Tests\Feature;

use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class UserResourceTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_endpoint_returns_only_allowed_attributes(): void
    {
        $user = User::factory()->create([
            'phone' => '+962790000001',
            'google_id' => 'test-google-id',
            'avatar_path' => 'avatars/test.jpg',
            'notification_preferences' => [
                'email' => true,
            ],
        ]);

        $user->refresh();

        $token = $user->createToken('test-token')->plainTextToken;

        $this->withToken($token)
            ->getJson('/api/v1/user')
            ->assertOk()
            ->assertExactJson([
                'success' => true,
                'message' => 'User retrieved successfully.',
                'data' => [
                    'id' => $user->id,
                    'full_name' => $user->full_name,
                    'email' => $user->email,
                    'phone' => $user->phone,
                    'role' => 'seeker',
                    'status' => 'active',
                    'email_verified_at' => $user->email_verified_at->toISOString(),
                ],
            ]);
    }

    public function test_resource_handles_nullable_attributes(): void
    {
        $user = User::factory()->unverified()->make([
            'phone' => null,
        ]);

        $data = UserResource::make($user)->resolve(request());

        $this->assertArrayHasKey('phone', $data);
        $this->assertArrayHasKey('email_verified_at', $data);

        $this->assertNull($data['phone']);
        $this->assertNull($data['email_verified_at']);
    }
}