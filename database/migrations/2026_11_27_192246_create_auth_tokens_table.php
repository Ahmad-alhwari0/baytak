<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_tokens', function (Blueprint $table) {
            $table->id();

            $table->foreignId('user_id')
                ->constrained('users')
                ->cascadeOnDelete();

            $table->enum('purpose', [
                'email_verification',
                'password_reset',
                'admin_login',
            ]);

            $table->char('token_hash', 64);

            $table->unsignedTinyInteger('attempts')->default(0);
            $table->unsignedTinyInteger('request_count')->default(0);

            $table->timestamp('request_window_started_at')->nullable();
            $table->timestamp('last_sent_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('locked_until')->nullable();
            $table->timestamp('consumed_at')->nullable();

            $table->timestamps();

            $table->unique(['user_id', 'purpose']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_tokens');
    }
};