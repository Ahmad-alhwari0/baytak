<?php

namespace Tests\Feature;

use App\Http\Requests\Auth\RegisterRequest;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class RegistrationValidationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::post(
            '/api/v1/__tests/register-validation',
            function (RegisterRequest $request) {
                return response()->json(
                    $request->safe()->except(['password'])
                );
            }
        );
    }

    #[DataProvider('allowedRoles')]
    public function test_registration_accepts_allowed_roles(
        string $role
    ): void {
        $this->postJson(
            '/api/v1/__tests/register-validation',
            $this->validPayload(['role' => $role])
        )
            ->assertOk()
            ->assertJsonPath('role', $role)
            ->assertJsonMissingPath('password');
    }

    public static function allowedRoles(): array
    {
        return [
            'seeker' => ['seeker'],
            'owner' => ['owner'],
        ];
    }

    public function test_registration_requires_all_required_fields(): void
    {
        $this->postJson(
            '/api/v1/__tests/register-validation',
            []
        )
            ->assertStatus(422)
            ->assertJsonPath('success', false)
            ->assertJsonValidationErrors([
                'full_name',
                'email',
                'password',
                'role',
            ]);
    }

    public function test_email_is_normalized_before_validation(): void
    {
        $this->postJson(
            '/api/v1/__tests/register-validation',
            $this->validPayload([
                'email' => '  USER@Example.com  ',
            ])
        )
            ->assertOk()
            ->assertJsonPath('email', 'user@example.com');
    }

    #[DataProvider('invalidPayloads')]
    public function test_registration_rejects_invalid_data(
        array $overrides,
        string $field
    ): void {
        $this->postJson(
            '/api/v1/__tests/register-validation',
            $this->validPayload($overrides)
        )
            ->assertStatus(422)
            ->assertJsonPath('success', false)
            ->assertJsonValidationErrors([$field]);
    }

    public static function invalidPayloads(): array
    {
        return [
            'admin role' => [
                ['role' => 'admin'],
                'role',
            ],

            'unknown role' => [
                ['role' => 'super_admin'],
                'role',
            ],

            'invalid role type' => [
                ['role' => ['owner']],
                'role',
            ],

            'invalid email' => [
                ['email' => 'invalid-email'],
                'email',
            ],

            'invalid email type' => [
                ['email' => ['user@example.com']],
                'email',
            ],

            'full name too long' => [
                ['full_name' => str_repeat('a', 151)],
                'full_name',
            ],

            'invalid full name type' => [
                ['full_name' => ['Test User']],
                'full_name',
            ],

            'short password' => [
                [
                    'password' => 'short',
                    'password_confirmation' => 'short',
                ],
                'password',
            ],

            'password exceeds 72 bytes' => [
                [
                    'password' => str_repeat('a', 73),
                    'password_confirmation' => str_repeat('a', 73),
                ],
                'password',
            ],

            'multibyte password exceeds 72 bytes' => [
                [
                    'password' => str_repeat('أ', 37),
                    'password_confirmation' => str_repeat('أ', 37),
                ],
                'password',
            ],

            'password contains null byte' => [
                [
                    'password' => str_repeat('a', 15)."\0",
                    'password_confirmation' => str_repeat('a', 15)."\0",
                ],
                'password',
            ],

            'password confirmation mismatch' => [
                [
                    'password_confirmation' => 'Different-password',
                ],
                'password',
            ],
        ];
    }

    public function test_password_confirmation_is_required(): void
    {
        $payload = $this->validPayload();

        unset($payload['password_confirmation']);

        $this->postJson(
            '/api/v1/__tests/register-validation',
            $payload
        )
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    public function test_password_length_boundaries_are_accepted(): void
    {
        foreach ([15, 72] as $length) {
            $password = str_repeat('a', $length);

            $this->postJson(
                '/api/v1/__tests/register-validation',
                $this->validPayload([
                    'password' => $password,
                    'password_confirmation' => $password,
                ])
            )->assertOk();
        }
    }

    public function test_sensitive_fields_are_excluded_from_validated_data(): void
    {
        $this->postJson(
            '/api/v1/__tests/register-validation',
            $this->validPayload([
                'id' => 999,
                'status' => 'active',
                'google_id' => 'fake-google-id',
                'email_verified_at' => '2026-01-01 00:00:00',
                'deleted_at' => null,
                'phone' => '+962790000001',
            ])
        )
            ->assertOk()
            ->assertExactJson([
                'full_name' => 'Test User',
                'email' => 'test@example.com',
                'role' => 'seeker',
            ]);
    }

    private function validPayload(array $overrides = []): array
    {
        return array_replace([
            'full_name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'Secure-test-password123',
            'password_confirmation' => 'Secure-test-password123',
            'role' => 'seeker',
        ], $overrides);
    }
}