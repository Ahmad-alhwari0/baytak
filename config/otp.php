<?php

return [
    'hash_key' => env('OTP_HASH_KEY'),

    'expires_in_minutes' => 5,

    'max_attempts' => 3,

    'resend_cooldown_seconds' => 60,

    'max_requests' => 5,

    'request_window_minutes' => 15,

    'lock_minutes' => 15,
];