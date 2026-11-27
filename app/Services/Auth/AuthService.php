<?php

namespace App\Services\Auth;

use App\Enums\AuthTokenPurpose;
use App\Enums\UserRole;
use App\Enums\UserStatus;
use App\Models\User;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

class AuthService
{
    public function __construct(
        private readonly AuthTokenService $authTokenService
    ) {
    }

    public function beginRegistration(
        string $fullName,
        string $email,
        UserRole $role
    ): ?string {
        if (!in_array($role, [
            UserRole::SEEKER,
            UserRole::OWNER,
        ], true)) {
            throw new InvalidArgumentException(
                'Unsupported registration role.'
            );
        }

        return DB::transaction(function () use (
            $fullName,
            $email,
            $role
        ) {
            $user = $this->findUserForUpdate($email);

            if ($user === null) {
                $user = new User();

                $user->full_name = $fullName;
                $user->email = $email;
                $user->password = null;
                $user->role = $role;
                $user->status = UserStatus::ACTIVE;
                $user->email_verified_at = null;

                try {
                    $user->save();
                } catch (UniqueConstraintViolationException $exception) {
                    $user = $this->findUserForUpdate($email);

                    if ($user === null) {
                        throw $exception;
                    }
                }
            }

            if (
                $user->trashed() ||
                $user->status !== UserStatus::ACTIVE ||
                $user->email_verified_at !== null ||
                $user->google_id !== null ||
                !in_array($user->role, [
                    UserRole::SEEKER,
                    UserRole::OWNER,
                ], true)
            ) {
                return null;
            }

            return $this->authTokenService->issue(
                $user,
                AuthTokenPurpose::EMAIL_VERIFICATION
            );
        }, attempts: 3);
    }

    private function findUserForUpdate(string $email): ?User
    {
        return User::query()
            ->withTrashed()
            ->where('email', $email)
            ->lockForUpdate()
            ->first();
    }
}