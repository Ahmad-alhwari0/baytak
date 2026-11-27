<?php

namespace App\Enums;

enum UserRole: string
{
    case SEEKER = 'seeker';
    case OWNER = 'owner';
    case ADMIN = 'admin';
}