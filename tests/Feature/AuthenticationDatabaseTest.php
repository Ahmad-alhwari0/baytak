<?php

namespace Tests\Feature;

use App\Enums\AuthTokenPurpose;
use App\Enums\UserRole;
use App\Enums\UserStatus;
use App\Models\AuthToken;
use App\Models\User;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class AuthenticationDatabaseTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_be_created(): void
    {
        $user = User::factory()->create();

        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'email' => $user->email,
            'role' => UserRole::SEEKER->value,
            'status' => UserStatus::ACTIVE->value,
        ]);

        $this->assertSame(UserRole::SEEKER, $user->role);
        $this->assertSame(UserStatus::ACTIVE, $user->status);
        $this->assertTrue(Hash::check('password', $user->password));
    }

    public function test_duplicate_user_email_is_rejected(): void
    {
        $user = User::factory()->create();

        $this->expectException(
            UniqueConstraintViolationException::class
        );

        User::factory()->create([
            'email' => $user->email,
        ]);
    }

    public function test_user_can_have_tokens_for_different_purposes(): void
    {
        $user = User::factory()->create();

        $token = $this->createAuthToken(
            $user,
            AuthTokenPurpose::EMAIL_VERIFICATION
        );

        $this->createAuthToken(
            $user,
            AuthTokenPurpose::PASSWORD_RESET
        );

        $this->assertSame(2, $user->authTokens()->count());

        $this->assertTrue($token->user->is($user));

        $this->assertSame(
            AuthTokenPurpose::EMAIL_VERIFICATION,
            $token->purpose
        );
    }

    public function test_duplicate_token_purpose_is_rejected(): void
    {
        $user = User::factory()->create();

        $this->createAuthToken(
            $user,
            AuthTokenPurpose::EMAIL_VERIFICATION
        );

        $this->expectException(
            UniqueConstraintViolationException::class
        );

        $this->createAuthToken(
            $user,
            AuthTokenPurpose::EMAIL_VERIFICATION
        );
    }

    public function test_user_can_be_soft_deleted(): void
    {
        $user = User::factory()->create();

        $user->delete();

        $this->assertSoftDeleted('users', [
            'id' => $user->id,
        ]);

        $this->assertNull(User::find($user->id));
    }

    public function test_auth_tokens_are_deleted_when_user_is_permanently_deleted(): void
    {
        $user = User::factory()->create();

        $token = $this->createAuthToken(
            $user,
            AuthTokenPurpose::EMAIL_VERIFICATION
        );

        $user->forceDelete();

        $this->assertDatabaseMissing('auth_tokens', [
            'id' => $token->id,
        ]);

        $this->assertDatabaseMissing('users', [
            'id' => $user->id,
        ]);
    }

    private function createAuthToken(
        User $user,
        AuthTokenPurpose $purpose
    ): AuthToken {
        $token = new AuthToken;

        $token->purpose = $purpose;
        $token->token_hash = str_repeat('a', 64);
        $token->expires_at = now()->addMinutes(5);

        $user->authTokens()->save($token);

        return $token;
    }
}