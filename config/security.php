<?php declare(strict_types=1);

/**
 * Security Configuration
 *
 * This file contains configuration options for the security middleware package.
 * Copy this file to your application's config directory and customize as needed.
 *
 * @package lalaz/security
 */

return [
    /*
    |--------------------------------------------------------------------------
    | CORS Configuration
    |--------------------------------------------------------------------------
    |
    | Cross-Origin Resource Sharing (CORS) settings control which external
    | origins can access your application's resources.
    |
    */
    'cors' => [
        // Enable or disable CORS handling
        'enabled' => true,

        // Allowed origins ('*' for all, or array of specific URLs)
        // Use ['*'] for development, specific origins for production
        'allowed_origins' => ['*'],

        // Allowed HTTP methods
        'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

        // Allowed request headers
        'allowed_headers' => [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'Accept',
            'Origin',
        ],

        // Headers exposed to the browser
        'exposed_headers' => [],

        // Preflight cache duration (seconds)
        'max_age' => 86400,

        // Allow credentials (cookies, authorization headers)
        'supports_credentials' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting Configuration
    |--------------------------------------------------------------------------
    |
    | Configure rate limiting to protect your application from abuse.
    | Different limiters can be created for different routes.
    |
    */
    'rate_limit' => [
        // Default rate limit settings
        'default' => [
            'max_attempts' => 60,
            'decay_minutes' => 1,
            'key' => 'ip', // 'ip', 'user', 'route', or closure
        ],

        // API rate limit (higher limit for authenticated users)
        'api' => [
            'max_attempts' => 100,
            'decay_minutes' => 1,
            'key' => 'user',
        ],

        // Login rate limit (strict to prevent brute force)
        'login' => [
            'max_attempts' => 5,
            'decay_minutes' => 15,
            'key' => 'ip',
        ],

        // Password reset rate limit
        'password_reset' => [
            'max_attempts' => 3,
            'decay_minutes' => 60,
            'key' => 'ip',
        ],

        // Registration rate limit
        'registration' => [
            'max_attempts' => 5,
            'decay_minutes' => 60,
            'key' => 'ip',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Headers (Helmet) Configuration
    |--------------------------------------------------------------------------
    |
    | Security headers protect against common web vulnerabilities like XSS,
    | clickjacking, and MIME sniffing.
    |
    */
    'helmet' => [
        // Content Security Policy
        // Set to null to disable, or provide a policy string
        'content_security_policy' => "default-src 'self'",

        // X-Content-Type-Options: nosniff
        'no_sniff' => true,

        // X-Frame-Options: DENY, SAMEORIGIN, or null to disable
        'frame_options' => 'SAMEORIGIN',

        // X-XSS-Protection header (legacy, for older browsers)
        'xss_protection' => true,

        // Referrer-Policy
        'referrer_policy' => 'strict-origin-when-cross-origin',

        // HTTP Strict Transport Security (HSTS)
        // Set to null to disable
        'hsts' => [
            'max_age' => 31536000, // 1 year
            'include_subdomains' => true,
            'preload' => false,
        ],

        // Permissions-Policy (formerly Feature-Policy)
        // Set to null to disable
        'permissions_policy' => null,

        // Remove X-Powered-By header
        'hide_powered_by' => true,

        // Cross-Origin-Embedder-Policy
        'cross_origin_embedder_policy' => null,

        // Cross-Origin-Opener-Policy
        'cross_origin_opener_policy' => 'same-origin',

        // Cross-Origin-Resource-Policy
        'cross_origin_resource_policy' => 'same-origin',
    ],
];
