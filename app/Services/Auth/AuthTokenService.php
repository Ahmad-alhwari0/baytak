<?php

namespace App\Services\Auth;

use App\Enums\AuthTokenPurpose;
use App\Models\AuthToken;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use RuntimeException;

class AuthTokenService
{
    public function issue(
        User $user,
        AuthTokenPurpose $purpose
    ): ?string {
        return DB::transaction(function () use ($user, $purpose) {
            $token = $this->findLockedToken($user, $purpose);

            $now = now()->toImmutable();

            if ($token === null) {
                $token = new AuthToken();

                $token->user_id = $user->getKey();
                $token->purpose = $purpose;
                $token->attempts = 0;
                $token->request_count = 0;
            }

            // Reject requests during an active lock.
            if ($token->locked_until !== null) {
                if ($token->locked_until->gt($now)) {
                    return null;
                }

                $token->locked_until = null;
                $token->attempts = 0;
            }

            // Enforce resend cooldown.
            if (
                $token->last_sent_at !== null &&
                $token->last_sent_at->copy()
                    ->addSeconds(config('otp.resend_cooldown_seconds'))
                    ->gt($now)
            ) {
                return null;
            }

            // Start a new request window when necessary.
            if (
                $token->request_window_started_at === null ||
                $token->request_window_started_at->copy()
                    ->addMinutes(config('otp.request_window_minutes'))
                    ->lte($now)
            ) {
                $token->request_window_started_at = $now;
                $token->request_count = 0;
            }

            // Enforce the request limit.
            if ($token->request_count >= config('otp.max_requests')) {
                return null;
            }

            // Generate a code different from the previous code.
            do {
                $code = sprintf('%06d', random_int(0, 999999));

                $hash = $this->hashCode($user, $purpose, $code);
            } while ($hash === $token->token_hash);

            $token->token_hash = $hash;
            $token->request_count++;
            $token->last_sent_at = $now;

            $token->expires_at = $now->addMinutes(
                config('otp.expires_in_minutes')
            );

            $token->consumed_at = null;

            $token->save();

            return $code;
        });
    }

    public function verifyAndConsume(
        User $user,
        AuthTokenPurpose $purpose,
        #[\SensitiveParameter] string $code
    ): bool {
        if (preg_match('/\A[0-9]{6}\z/', $code) !== 1) {
            return false;
        }

        return DB::transaction(function () use ($user, $purpose, $code) {
            $token = $this->findLockedToken($user, $purpose);

            $now = now()->toImmutable();

            if ($token === null) {
                return false;
            }

            if ($token->consumed_at !== null) {
                return false;
            }

            if ($token->expires_at->lte($now)) {
                return false;
            }

            if (
                $token->locked_until !== null &&
                $token->locked_until->gt($now)
            ) {
                return false;
            }

            if ($token->attempts >= config('otp.max_attempts')) {
                return false;
            }

            $hash = $this->hashCode($user, $purpose, $code);

            if (!hash_equals($token->token_hash, $hash)) {
                $token->attempts++;

                if ($token->attempts >= config('otp.max_attempts')) {
                    $token->locked_until = $now->addMinutes(
                        config('otp.lock_minutes')
                    );
                }

                $token->save();

                return false;
            }

            $token->consumed_at = $now;
            $token->attempts = 0;

            $token->save();

            return true;
        });
    }

    private function findLockedToken(
        User $user,
        AuthTokenPurpose $purpose
    ): ?AuthToken {
        User::query()
            ->whereKey($user->getKey())
            ->lockForUpdate()
            ->firstOrFail(['id']);

        return AuthToken::query()
            ->where('user_id', $user->getKey())
            ->where('purpose', $purpose->value)
            ->lockForUpdate()
            ->first();
    }

    private function hashCode(
        User $user,
        AuthTokenPurpose $purpose,
        #[\SensitiveParameter] string $code
    ): string {
        $key = config('otp.hash_key');

        if (
            !is_string($key) ||
            preg_match('/\A[0-9a-f]{64}\z/i', $key) !== 1
        ) {
            throw new RuntimeException(
                'OTP hash key is missing or invalid.'
            );
        }

        $payload = sprintf(
            '%s:%s:%s',
            $user->getKey(),
            $purpose->value,
            $code
        );

        return hash_hmac(
            'sha256',
            $payload,
            hex2bin($key)
        );
    }
}