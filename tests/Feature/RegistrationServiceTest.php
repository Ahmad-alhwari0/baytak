<?php

namespace Tests\Feature;

use App\Enums\AuthTokenPurpose;
use App\Enums\UserRole;
use App\Enums\UserStatus;
use App\Models\AuthToken;
use App\Models\User;
use App\Services\Auth\AuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\TestCase;

class RegistrationServiceTest extends TestCase
{
    use RefreshDatabase;

    private AuthService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(now()->startOfSecond());

        config([
            'otp.hash_key' => str_repeat('ab', 32),
        ]);

        $this->service = app(AuthService::class);
    }

    #[DataProvider('allowedRoles')]
    public function test_registration_creates_pending_account_and_otp(
        UserRole $role
    ): void {
        $code = $this->service->beginRegistration(
            'Test User',
            'test@example.com',
            $role
        );

        $this->assertIsString($code);

        $this->assertMatchesRegularExpression(
            '/\A[0-9]{6}\z/',
            $code
        );

        $user = User::query()
            ->where('email', 'test@example.com')
            ->firstOrFail();

        $this->assertSame('Test User', $user->full_name);
        $this->assertSame($role, $user->role);
        $this->assertSame(UserStatus::ACTIVE, $user->status);

        $this->assertNull($user->password);
        $this->assertNull($user->email_verified_at);
        $this->assertNull($user->google_id);
        $this->assertNull($user->phone);

        $token = $this->tokenFor($user);

        $this->assertSame(
            AuthTokenPurpose::EMAIL_VERIFICATION,
            $token->purpose
        );

        $this->assertSame(1, $token->request_count);
        $this->assertNull($token->consumed_at);

        $expectedHash = hash_hmac(
            'sha256',
            $user->id.':email_verification:'.$code,
            hex2bin(config('otp.hash_key'))
        );

        $this->assertSame($expectedHash, $token->token_hash);

        $this->assertDatabaseCount('users', 1);
        $this->assertDatabaseCount('auth_tokens', 1);
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public static function allowedRoles(): array
    {
        return [
            'seeker' => [UserRole::SEEKER],
            'owner' => [UserRole::OWNER],
        ];
    }

    public function test_repeated_registration_preserves_account_and_enforces_otp_limits(): void
    {
        $firstCode = $this->service->beginRegistration(
            'Original Name',
            'test@example.com',
            UserRole::SEEKER
        );

        $this->assertNotNull($firstCode);

        $user = User::query()
            ->where('email', 'test@example.com')
            ->firstOrFail();

        $originalAttributes = $user->getRawOriginal();
        $originalHash = $this->tokenFor($user)->token_hash;

        // Repeated registration during cooldown.
        $this->assertNull(
            $this->service->beginRegistration(
                'Modified Name',
                'test@example.com',
                UserRole::OWNER
            )
        );

        $this->assertSame(
            1,
            $this->tokenFor($user)->request_count
        );

        $this->assertSame(
            $originalHash,
            $this->tokenFor($user)->token_hash
        );

        $this->travel(60)->seconds();

        // Registration after cooldown.
        $secondCode = $this->service->beginRegistration(
            'Modified Name',
            'test@example.com',
            UserRole::OWNER
        );

        $this->assertNotNull($secondCode);
        $this->assertNotSame($firstCode, $secondCode);

        $this->assertSame(
            $originalAttributes,
            $user->refresh()->getRawOriginal()
        );

        $this->assertSame(
            2,
            $this->tokenFor($user)->request_count
        );

        $this->assertNotSame(
            $originalHash,
            $this->tokenFor($user)->token_hash
        );

        $this->assertDatabaseCount('users', 1);
        $this->assertDatabaseCount('auth_tokens', 1);
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    #[DataProvider('ineligibleAccounts')]
    public function test_registration_does_not_modify_ineligible_accounts(
        array $attributes
    ): void {
        $user = User::factory()
            ->unverified()
            ->create($attributes);

        $originalAttributes = $user->refresh()->getRawOriginal();

        $code = $this->service->beginRegistration(
            'Modified Name',
            $user->email,
            UserRole::OWNER
        );

        $this->assertNull($code);

        $this->assertSame(
            $originalAttributes,
            $user->refresh()->getRawOriginal()
        );

        $this->assertDatabaseCount('users', 1);
        $this->assertDatabaseCount('auth_tokens', 0);
        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public static function ineligibleAccounts(): array
    {
        return [
            'verified account' => [
                [
                    'email_verified_at' => '2026-01-01 00:00:00',
                ],
            ],

            'suspended account' => [
                [
                    'status' => UserStatus::SUSPENDED,
                ],
            ],

            'banned account' => [
                [
                    'status' => UserStatus::BANNED,
                ],
            ],

            'admin account' => [
                [
                    'role' => UserRole::ADMIN,
                ],
            ],

            'google linked account' => [
                [
                    'google_id' => 'test-google-id',
                    'password' => null,
                ],
            ],
        ];
    }

    public function test_registration_does_not_restore_soft_deleted_account(): void
    {
        $user = User::factory()
            ->unverified()
            ->create();

        $user->delete();

        $originalAttributes = User::withTrashed()
            ->findOrFail($user->id)
            ->getRawOriginal();

        $code = $this->service->beginRegistration(
            'Modified Name',
            $user->email,
            UserRole::OWNER
        );

        $this->assertNull($code);

        $this->assertSoftDeleted('users', [
            'id' => $user->id,
        ]);

        $this->assertSame(
            $originalAttributes,
            User::withTrashed()
                ->findOrFail($user->id)
                ->getRawOriginal()
        );

        $this->assertDatabaseCount('users', 1);
        $this->assertDatabaseCount('auth_tokens', 0);
    }

    public function test_service_rejects_direct_admin_registration(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->expectExceptionMessage(
            'Unsupported registration role.'
        );

        try {
            $this->service->beginRegistration(
                'Admin User',
                'admin@example.com',
                UserRole::ADMIN
            );
        } finally {
            $this->assertDatabaseCount('users', 0);
            $this->assertDatabaseCount('auth_tokens', 0);
        }
    }

    public function test_registration_is_rolled_back_when_otp_generation_fails(): void
    {
        config(['otp.hash_key' => null]);

        $this->expectException(RuntimeException::class);

        $this->expectExceptionMessage(
            'OTP hash key is missing or invalid.'
        );

        try {
            $this->service->beginRegistration(
                'Test User',
                'test@example.com',
                UserRole::SEEKER
            );
        } finally {
            $this->assertDatabaseCount('users', 0);
            $this->assertDatabaseCount('auth_tokens', 0);
            $this->assertDatabaseCount('personal_access_tokens', 0);
        }
    }

    private function tokenFor(User $user): AuthToken
    {
        return AuthToken::query()
            ->where('user_id', $user->id)
            ->where(
                'purpose',
                AuthTokenPurpose::EMAIL_VERIFICATION->value
            )
            ->firstOrFail();
    }
}