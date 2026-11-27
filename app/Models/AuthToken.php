<?php

namespace App\Models;

use App\Enums\AuthTokenPurpose;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AuthToken extends Model
{
    protected $guarded = ['*'];

    protected $hidden = [
        'token_hash',
    ];

    protected function casts(): array
    {
        return [
            'purpose' => AuthTokenPurpose::class,
            'attempts' => 'integer',
            'request_count' => 'integer',
            'request_window_started_at' => 'datetime',
            'last_sent_at' => 'datetime',
            'expires_at' => 'datetime',
            'locked_until' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
