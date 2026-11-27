<?php

namespace App\Notifications\Auth;

use App\Enums\AuthTokenPurpose;
use App\Enums\UserStatus;
use App\Models\AuthToken;
use App\Models\User;
use DateTime;
use DateTimeImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use RuntimeException;
use SensitiveParameter;

class EmailVerificationNotification extends Notification implements
    ShouldQueue,
    ShouldBeEncrypted
{
    use Queueable;

    public int $maxExceptions = 3;

    public function __construct(
        #[SensitiveParameter]
        private readonly string $code,
        private readonly string $recipientEmail,
        private readonly string $tokenHash,
        private readonly DateTimeImmutable $expiresAt
    ) {
        $this->afterCommit();
    }

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function backoff(): int
    {
        return 15;
    }

    public function retryUntil(): DateTime
    {
        return DateTime::createFromImmutable($this->expiresAt);
    }

    public function shouldSend(
        object $notifiable,
        string $channel
    ): bool {
        $now = now();

        if (
            $channel !== 'mail' ||
            !($notifiable instanceof User) ||
            $notifiable->trashed() ||
            $notifiable->status !== UserStatus::ACTIVE ||
            $notifiable->email_verified_at !== null ||
            $notifiable->email !== $this->recipientEmail ||
            $now->gte($this->expiresAt)
        ) {
            return false;
        }

        return AuthToken::query()
            ->where('user_id', $notifiable->getKey())
            ->where(
                'purpose',
                AuthTokenPurpose::EMAIL_VERIFICATION->value
            )
            ->where('token_hash', $this->tokenHash)
            ->where('expires_at', $this->expiresAt)
            ->where('expires_at', '>', $now)
            ->whereNull('consumed_at')
            ->where('attempts', '<', config('otp.max_attempts'))
            ->where(function ($query) use ($now) {
                $query->whereNull('locked_until')
                    ->orWhere('locked_until', '<=', $now);
            })
            ->exists();
    }

    public function toMail(object $notifiable): MailMessage
    {
        $mailer = config('mail.default');

        if (
            !in_array($mailer, ['array', 'smtp'], true) ||
            config("mail.mailers.{$mailer}.transport") !== $mailer ||
            (
                $mailer === 'array' &&
                !app()->environment('local', 'testing')
            )
        ) {
            throw new RuntimeException(
                'OTP mailer is not configured safely.'
            );
        }

        return (new MailMessage)
            ->mailer($mailer)
            ->subject('Verify your Baytak email address')
            ->greeting('Welcome to Baytak!')
            ->line('Your email verification code is:')
            ->line($this->code)
            ->line(
                'This code expires '.config('otp.expires_in_minutes').
                ' minutes after it was issued.'
            )
            ->line('Never share this code with anyone.')
            ->line(
                'If you did not request this code, you can ignore this email.'
            )
            ->salutation('The Baytak Team');
    }
}