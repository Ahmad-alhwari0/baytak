<?php

namespace Tests\Feature;

use App\Enums\AuthTokenPurpose;
use App\Enums\UserStatus;
use App\Models\AuthToken;
use App\Models\User;
use App\Notifications\Auth\EmailVerificationNotification;
use App\Services\Auth\AuthTokenService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\TestCase;

class EmailVerificationNotificationTest extends TestCase
{
    use RefreshDatabase;

    private User $user;

    private AuthToken $token;

    private AuthTokenService $service;

    private string $code;

    private EmailVerificationNotification $notification;

    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(now()->startOfSecond());

        config([
            'otp.hash_key' => str_repeat('ab', 32),
            'mail.default' => 'array',
            'mail.from.address' => 'no-reply@example.test',
            'mail.from.name' => 'Baytak',
            'queue.default' => 'database',
            'queue.connections.database.connection' => 'mysql',
            'queue.connections.database.queue' => 'otp-tests',
            'queue.connections.database.after_commit' => false,
        ]);

        $this->service = app(AuthTokenService::class);

        $this->user = User::factory()
            ->unverified()
            ->create([
                'password' => null,
            ]);

        $code = $this->service->issue(
            $this->user,
            AuthTokenPurpose::EMAIL_VERIFICATION
        );

        $this->assertNotNull($code);

        $this->code = $code;

        $this->token = AuthToken::query()
            ->where('user_id', $this->user->id)
            ->where(
                'purpose',
                AuthTokenPurpose::EMAIL_VERIFICATION->value
            )
            ->firstOrFail();

        $this->notification = new EmailVerificationNotification(
            code: $this->code,
            recipientEmail: $this->user->email,
            tokenHash: $this->token->token_hash,
            expiresAt: $this->token->expires_at->toImmutable()
        );
    }

    public function test_valid_notification_is_encrypted_queued_and_delivered(): void
    {
        $this->assertTrue(
            $this->notification->shouldSend($this->user, 'mail')
        );

        DB::transaction(function (): void {
            $this->user->notify($this->notification);

            $this->assertDatabaseCount('jobs', 0);
        });

        $this->assertDatabaseCount('jobs', 1);

        $record = DB::table('jobs')->first();

        $payload = json_decode(
            $record->payload,
            true,
            512,
            JSON_THROW_ON_ERROR
        );

        $encryptedCommand = $payload['data']['command'];

        $serializedCode = 's:6:"'.$this->code.'";';

        // The serialized OTP must not appear in plaintext.
        $this->assertStringNotContainsString(
            $serializedCode,
            $encryptedCommand
        );

        // Verify that Laravel actually encrypted the command.
        $decryptedCommand = Crypt::decrypt($encryptedCommand);

        $this->assertStringContainsString(
            EmailVerificationNotification::class,
            $decryptedCommand
        );

        $this->assertStringContainsString(
            $serializedCode,
            $decryptedCommand
        );

        $this->assertSame(3, $payload['maxExceptions']);

        $this->assertSame(
            15,
            (int) $payload['backoff']
        );

        $this->assertSame(
            $this->token->expires_at->getTimestamp(),
            $payload['retryUntil']
        );

        $this->processQueuedNotification();

        $this->assertDatabaseCount('jobs', 0);

        $messages = Mail::mailer('array')
            ->getSymfonyTransport()
            ->messages();

        $this->assertCount(1, $messages);

        $email = $messages->first()->getOriginalMessage();

        $this->assertSame(
            'Verify your Baytak email address',
            $email->getSubject()
        );

        $this->assertSame(
            $this->user->email,
            $email->getTo()[0]->getAddress()
        );

        $this->assertStringContainsString(
            $this->code,
            (string) $email->getTextBody()
        );
    }

    public function test_notification_is_not_queued_when_transaction_rolls_back(): void
    {
        DB::beginTransaction();

        try {
            $this->user->notify($this->notification);

            $this->assertDatabaseCount('jobs', 0);
        } finally {
            DB::rollBack();
        }

        $this->assertDatabaseCount('jobs', 0);
    }

    public function test_queued_notification_skips_replaced_otp(): void
    {
        $this->user->notify($this->notification);

        $this->assertDatabaseCount('jobs', 1);

        $this->travel(60)->seconds();

        $newCode = $this->service->issue(
            $this->user,
            AuthTokenPurpose::EMAIL_VERIFICATION
        );

        $this->assertNotNull($newCode);
        $this->assertNotSame($this->code, $newCode);

        $this->processQueuedNotification();

        $this->assertDatabaseCount('jobs', 0);

        $this->assertCount(
            0,
            Mail::mailer('array')
                ->getSymfonyTransport()
                ->messages()
        );
    }

    #[DataProvider('invalidTokenStates')]
    public function test_notification_rejects_invalid_token_states(
        string $state
    ): void {
        switch ($state) {
            case 'expired':
                $this->travel(5)->minutes();
                break;

            case 'replaced':
                $this->travel(60)->seconds();

                $this->assertNotNull(
                    $this->service->issue(
                        $this->user,
                        AuthTokenPurpose::EMAIL_VERIFICATION
                    )
                );
                break;

            case 'consumed':
                $this->assertTrue(
                    $this->service->verifyAndConsume(
                        $this->user,
                        AuthTokenPurpose::EMAIL_VERIFICATION,
                        $this->code
                    )
                );
                break;

            case 'locked':
                $wrongCode = $this->code === '000000'
                    ? '111111'
                    : '000000';

                for ($attempt = 1; $attempt <= 3; $attempt++) {
                    $this->assertFalse(
                        $this->service->verifyAndConsume(
                            $this->user,
                            AuthTokenPurpose::EMAIL_VERIFICATION,
                            $wrongCode
                        )
                    );
                }
                break;

            case 'missing':
                $this->token->delete();
                break;
        }

        $this->assertFalse(
            $this->notification->shouldSend(
                $this->user,
                'mail'
            )
        );
    }

    public static function invalidTokenStates(): array
    {
        return [
            'expired otp' => ['expired'],
            'replaced otp' => ['replaced'],
            'consumed otp' => ['consumed'],
            'locked otp' => ['locked'],
            'missing otp record' => ['missing'],
        ];
    }

    #[DataProvider('ineligibleAccounts')]
    public function test_notification_rejects_ineligible_accounts(
        array $attributes
    ): void {
        $this->user->forceFill($attributes)->save();

        $this->assertFalse(
            $this->notification->shouldSend(
                $this->user->refresh(),
                'mail'
            )
        );
    }

    public static function ineligibleAccounts(): array
    {
        return [
            'suspended account' => [
                ['status' => UserStatus::SUSPENDED],
            ],

            'banned account' => [
                ['status' => UserStatus::BANNED],
            ],

            'verified account' => [
                ['email_verified_at' => '2026-01-01 00:00:00'],
            ],

            'changed email address' => [
                ['email' => 'changed@example.com'],
            ],
        ];
    }

    public function test_notification_rejects_soft_deleted_account(): void
    {
        $this->user->delete();

        $this->assertFalse(
            $this->notification->shouldSend(
                $this->user,
                'mail'
            )
        );
    }

    public function test_notification_uses_only_mail_channel(): void
    {
        $this->assertSame(
            ['mail'],
            $this->notification->via($this->user)
        );

        $this->assertFalse(
            $this->notification->shouldSend(
                $this->user,
                'database'
            )
        );
    }

    #[DataProvider('unsafeMailers')]
    public function test_notification_rejects_unsafe_mailers(
        string $mailer
    ): void {
        config([
            'mail.default' => $mailer,
            'mail.mailers.smtp.transport' => 'log',
        ]);

        $this->expectException(RuntimeException::class);

        $this->expectExceptionMessage(
            'OTP mailer is not configured safely.'
        );

        $this->notification->toMail($this->user);
    }

    public static function unsafeMailers(): array
    {
        return [
            'log mailer' => ['log'],
            'misconfigured smtp transport' => ['smtp'],
        ];
    }

    private function processQueuedNotification(): void
    {
        $job = Queue::connection('database')->pop('otp-tests');

        $this->assertNotNull($job);

        $job->fire();
    }
}