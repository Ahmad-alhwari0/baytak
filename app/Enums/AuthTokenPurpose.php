<?php

namespace App\Enums;

enum AuthTokenPurpose: string
{
    case EMAIL_VERIFICATION = 'email_verification';
    case PASSWORD_RESET = 'password_reset';
    case ADMIN_LOGIN = 'admin_login';
}