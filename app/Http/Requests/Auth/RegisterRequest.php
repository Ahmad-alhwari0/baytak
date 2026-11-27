<?php

namespace App\Http\Requests\Auth;

use App\Enums\UserRole;
use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    protected function prepareForValidation(): void
    {
        $email = $this->input('email');

        if (is_string($email)) {
            $this->merge([
                'email' => Str::lower(trim($email)),
            ]);
        }
    }

    public function rules(): array
    {
        return [
            'full_name' => [
                'bail',
                'required',
                'string',
                'max:150',
            ],

            'email' => [
                'bail',
                'required',
                'string',
                'max:254',
                'email:rfc',
            ],

            'password' => [
                'bail',
                'required',
                'string',
                'min:15',
                function (string $attribute, mixed $value, Closure $fail): void {
                    if (strlen($value) > 72 || str_contains($value, "\0")) {
                        $fail('The password exceeds the supported length or contains invalid characters.');
                    }
                },
                'confirmed',
            ],

            'role' => [
                'bail',
                'required',
                'string',
                Rule::enum(UserRole::class)->only([
                    UserRole::SEEKER,
                    UserRole::OWNER,
                ]),
            ],
        ];
    }
}