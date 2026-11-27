<?php

namespace Tests\Feature;

use App\Enums\AuthTokenPurpose;
use App\Models\AuthToken;
use App\Models\User;
use App\Services\Auth\AuthTokenService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\TestCase;

class AuthTokenServiceTest extends TestCase
{
    use RefreshDatabase;

    private const PURPOSE = AuthTokenPurpose::EMAIL_VERIFICATION;

    private AuthTokenService $service;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(now()->startOfSecond());

        config([
            'otp.hash_key' => str_repeat('ab', 32),
        ]);

        $this->service = app(AuthTokenService::class);

        $this->user = User::factory()->unverified()->create();
    }

    public function test_otp_is_generated_and_stored_as_hmac(): void
    {
        $code = $this->issueCode();

        $token = $this->token();

        $expectedHash = hash_hmac(
            'sha256',
            $this->user->id.':'.self::PURPOSE->value.':'.$code,
            hex2bin(config('otp.hash_key'))
        );

        $this->assertMatchesRegularExpression(
            '/\A[0-9]{6}\z/',
            $code
        );

        $this->assertSame($expectedHash, $token->token_hash);
        $this->assertNotSame($code, $token->token_hash);

        $this->assertSame(0, $token->attempts);
        $this->assertSame(1, $token->request_count);

        $this->assertNull($token->consumed_at);
        $this->assertNull($token->locked_until);

        $this->assertTrue(
            $token->expires_at->equalTo(now()->addMinutes(5))
        );

        $this->assertDatabaseCount('auth_tokens', 1);
    }

    public function test_correct_otp_is_consumed_and_cannot_be_reused(): void
    {
        $code = $this->issueCode();

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $this->wrongCode($code)
            )
        );

        $this->assertSame(1, $this->token()->attempts);

        $this->assertTrue(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $code
            )
        );

        $token = $this->token();

        $this->assertNotNull($token->consumed_at);
        $this->assertSame(0, $token->attempts);
        $this->assertSame(1, $token->request_count);

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $code
            )
        );
    }

    public function test_expired_otp_is_rejected(): void
    {
        $code = $this->issueCode();

        $this->travel(5)->minutes();

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $code
            )
        );

        $this->assertNull($this->token()->consumed_at);
        $this->assertSame(0, $this->token()->attempts);
    }

    public function test_resend_cooldown_and_previous_otp_invalidation(): void
    {
        $firstCode = $this->issueCode();

        $this->travel(59)->seconds();

        $this->assertNull(
            $this->service->issue(
                $this->user,
                self::PURPOSE
            )
        );

        $this->assertSame(1, $this->token()->request_count);

        $this->travel(1)->seconds();

        $secondCode = $this->issueCode();

        $this->assertNotSame($firstCode, $secondCode);
        $this->assertSame(2, $this->token()->request_count);

        $this->assertDatabaseCount('auth_tokens', 1);

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $firstCode
            )
        );

        $this->assertTrue(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $secondCode
            )
        );
    }

    public function test_three_failed_attempts_lock_otp_until_lock_expires(): void
    {
        $code = $this->issueCode();

        $wrongCode = $this->wrongCode($code);

        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $this->assertFalse(
                $this->service->verifyAndConsume(
                    $this->user,
                    self::PURPOSE,
                    $wrongCode
                )
            );

            $this->assertSame(
                $attempt,
                $this->token()->attempts
            );
        }

        $this->assertTrue(
            $this->token()->locked_until
                ->equalTo(now()->addMinutes(15))
        );

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $code
            )
        );

        $this->travel(899)->seconds();

        $this->assertNull(
            $this->service->issue(
                $this->user,
                self::PURPOSE
            )
        );

        $this->travel(1)->seconds();

        $newCode = $this->issueCode();

        $this->assertSame(0, $this->token()->attempts);
        $this->assertNull($this->token()->locked_until);

        $this->assertTrue(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $newCode
            )
        );
    }

    public function test_failed_attempts_are_preserved_after_resend(): void
    {
        $code = $this->issueCode();

        for ($attempt = 1; $attempt <= 2; $attempt++) {
            $this->assertFalse(
                $this->service->verifyAndConsume(
                    $this->user,
                    self::PURPOSE,
                    $this->wrongCode($code)
                )
            );
        }

        $this->travel(60)->seconds();

        $newCode = $this->issueCode();

        $this->assertSame(2, $this->token()->attempts);

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $this->wrongCode($newCode)
            )
        );

        $this->assertSame(3, $this->token()->attempts);
        $this->assertNotNull($this->token()->locked_until);
    }

    public function test_failed_attempts_are_preserved_after_otp_expiration(): void
    {
        $code = $this->issueCode();

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $this->wrongCode($code)
            )
        );

        $this->travel(5)->minutes();

        $this->issueCode();

        $this->assertSame(1, $this->token()->attempts);
    }

    public function test_request_limit_is_enforced_until_window_expires(): void
    {
        $startedAt = now()->toImmutable();

        $this->issueCode();

        for ($request = 2; $request <= 5; $request++) {
            $this->travel(60)->seconds();

            $this->issueCode();
        }

        $this->assertSame(5, $this->token()->request_count);

        $previousHash = $this->token()->token_hash;

        $this->travelTo(
            $startedAt->addMinutes(15)->subSecond()
        );

        $this->assertNull(
            $this->service->issue(
                $this->user,
                self::PURPOSE
            )
        );

        $this->assertSame(5, $this->token()->request_count);

        $this->assertSame(
            $previousHash,
            $this->token()->token_hash
        );

        $this->travel(1)->seconds();

        $this->issueCode();

        $this->assertSame(1, $this->token()->request_count);

        $this->assertTrue(
            $this->token()->request_window_started_at
                ->equalTo(now())
        );
    }

    public function test_verification_without_an_otp_record_is_rejected(): void
    {
        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                '123456'
            )
        );

        $this->assertDatabaseCount('auth_tokens', 0);
    }

    public function test_malformed_otp_codes_are_rejected(): void
    {
        $this->issueCode();

        $invalidCodes = [
            '',
            '12345',
            '1234567',
            'abcdef',
            '12345a',
            '١٢٣٤٥٦',
            ' 123456 ',
        ];

        foreach ($invalidCodes as $code) {
            $this->assertFalse(
                $this->service->verifyAndConsume(
                    $this->user,
                    self::PURPOSE,
                    $code
                )
            );
        }

        $this->assertSame(0, $this->token()->attempts);
        $this->assertNull($this->token()->consumed_at);
    }

    public function test_otp_purposes_are_independent(): void
    {
        $emailCode = $this->issueCode();

        $passwordCode = $this->issueCode(
            purpose: AuthTokenPurpose::PASSWORD_RESET
        );

        $adminCode = $this->issueCode(
            purpose: AuthTokenPurpose::ADMIN_LOGIN
        );

        $this->assertDatabaseCount('auth_tokens', 3);

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $this->wrongCode($emailCode)
            )
        );

        $this->assertSame(1, $this->token()->attempts);

        $this->assertSame(
            0,
            $this->token(
                purpose: AuthTokenPurpose::PASSWORD_RESET
            )->attempts
        );

        $this->assertTrue(
            $this->service->verifyAndConsume(
                $this->user,
                AuthTokenPurpose::PASSWORD_RESET,
                $passwordCode
            )
        );

        $this->assertTrue(
            $this->service->verifyAndConsume(
                $this->user,
                AuthTokenPurpose::ADMIN_LOGIN,
                $adminCode
            )
        );

        $this->assertNull($this->token()->consumed_at);
    }

    public function test_otp_tokens_are_independent_between_users(): void
    {
        $secondUser = User::factory()->unverified()->create();

        $firstCode = $this->issueCode();

        $secondCode = $this->issueCode($secondUser);

        $this->assertDatabaseCount('auth_tokens', 2);

        $this->assertFalse(
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $this->wrongCode($firstCode)
            )
        );

        $this->assertSame(1, $this->token()->attempts);
        $this->assertSame(0, $this->token($secondUser)->attempts);

        $this->assertTrue(
            $this->service->verifyAndConsume(
                $secondUser,
                self::PURPOSE,
                $secondCode
            )
        );

        $this->assertNull($this->token()->consumed_at);
    }

    #[DataProvider('invalidHashKeys')]
    public function test_invalid_hash_key_prevents_otp_issuance(
        ?string $key
    ): void {
        config(['otp.hash_key' => $key]);

        $this->expectException(RuntimeException::class);

        $this->expectExceptionMessage(
            'OTP hash key is missing or invalid.'
        );

        try {
            $this->service->issue(
                $this->user,
                self::PURPOSE
            );
        } finally {
            $this->assertDatabaseCount('auth_tokens', 0);
        }
    }

    public static function invalidHashKeys(): array
    {
        return [
            'missing key' => [null],
            'short key' => ['abc123'],
            'invalid hexadecimal key' => [str_repeat('z', 64)],
        ];
    }

    public function test_invalid_hash_key_prevents_otp_verification(): void
    {
        $code = $this->issueCode();

        config(['otp.hash_key' => null]);

        $this->expectException(RuntimeException::class);

        $this->expectExceptionMessage(
            'OTP hash key is missing or invalid.'
        );

        try {
            $this->service->verifyAndConsume(
                $this->user,
                self::PURPOSE,
                $code
            );
        } finally {
            $this->assertNull($this->token()->consumed_at);
            $this->assertSame(0, $this->token()->attempts);
        }
    }

    private function issueCode(
        ?User $user = null,
        AuthTokenPurpose $purpose = self::PURPOSE
    ): string {
        $code = $this->service->issue(
            $user ?? $this->user,
            $purpose
        );

        $this->assertNotNull($code);

        return $code;
    }

    private function token(
        ?User $user = null,
        AuthTokenPurpose $purpose = self::PURPOSE
    ): AuthToken {
        return AuthToken::query()
            ->where('user_id', ($user ?? $this->user)->id)
            ->where('purpose', $purpose->value)
            ->firstOrFail();
    }

    private function wrongCode(string $code): string
    {
        return $code === '000000'
            ? '111111'
            : '000000';
    }
}