<?php

namespace Tests\Feature;

use App\Support\ApiResponse;
use Tests\TestCase;

class ApiResponseTest extends TestCase
{
    public function test_success_response_has_standard_structure(): void
    {
        $response = ApiResponse::success(
            data: ['id' => 1],
            message: 'Created successfully.',
            status: 201
        );

        $this->assertSame(201, $response->getStatusCode());

        $this->assertSame([
            'success' => true,
            'message' => 'Created successfully.',
            'data' => ['id' => 1],
        ], $response->getData(true));
    }

    public function test_error_response_has_standard_structure(): void
    {
        $response = ApiResponse::error(
            message: 'Unauthenticated.',
            status: 401
        );

        $this->assertSame(401, $response->getStatusCode());

        $this->assertSame([
            'success' => false,
            'message' => 'Unauthenticated.',
            'errors' => null,
        ], $response->getData(true));
    }

    public function test_validation_error_response_contains_errors(): void
    {
        $errors = [
            'email' => ['The email field is required.'],
        ];

        $response = ApiResponse::error(
            message: 'Validation failed.',
            status: 422,
            errors: $errors
        );

        $this->assertSame(422, $response->getStatusCode());

        $this->assertSame([
            'success' => false,
            'message' => 'Validation failed.',
            'errors' => $errors,
        ], $response->getData(true));
    }
}