<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Tests\TestCase;

class DatabaseConfigurationTest extends TestCase
{
    public function test_application_uses_testing_database(): void
    {
        $this->assertSame('testing', app()->environment());

        $this->assertSame('mysql', config('database.default'));

        $this->assertSame(
            'baytak_test_db',
            DB::connection()->getDatabaseName()
        );

        $result = DB::selectOne(
            'SELECT DATABASE() AS database_name'
        );

        $this->assertSame(
            'baytak_test_db',
            $result->database_name
        );

        $account = DB::selectOne(
            'SELECT CURRENT_USER() AS account'
        );

        $this->assertSame(
            'baytak_test@127.0.0.1',
            $account->account
        );
    }
}