<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * CORS (Cross-Origin Resource Sharing) Middleware
 *
 * Handles CORS preflight requests and adds appropriate headers to responses.
 * Fully configurable to control which origins, methods, and headers are allowed.
 *
 * @example Basic usage - allow all origins:
 * ```php
 * $router->middleware(new CorsMiddleware());
 * ```
 *
 * @example Restrict to specific origins:
 * ```php
 * $router->middleware(new CorsMiddleware(
 *     allowedOrigins: ['https://example.com', 'https://app.example.com'],
 * ));
 * ```
 *
 * @example Full configuration:
 * ```php
 * $router->middleware(CorsMiddleware::fromConfig([
 *     'allowed_origins' => ['https://example.com'],
 *     'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE'],
 *     'allowed_headers' => ['Content-Type', 'Authorization', 'X-Requested-With'],
 *     'exposed_headers' => ['X-Custom-Header'],
 *     'max_age' => 86400,
 *     'supports_credentials' => true,
 * ]));
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 * @link https://lalaz.dev
 */
class CorsMiddleware implements MiddlewareInterface
{
    /**
     * @var array<string> Allowed origins ('*' for all, or specific URLs)
     */
    private array $allowedOrigins;

    /**
     * @var array<string> Allowed HTTP methods
     */
    private array $allowedMethods;

    /**
     * @var array<string> Allowed request headers
     */
    private array $allowedHeaders;

    /**
     * @var array<string> Headers exposed to the browser
     */
    private array $exposedHeaders;

    /**
     * @var int Preflight cache duration in seconds
     */
    private int $maxAge;

    /**
     * @var bool Whether to allow credentials (cookies, authorization headers)
     */
    private bool $supportsCredentials;

    /**
     * Create a new CORS middleware instance.
     *
     * @param array<string> $allowedOrigins Origins allowed to make requests. Use ['*'] for all.
     * @param array<string> $allowedMethods HTTP methods allowed for CORS requests.
     * @param array<string> $allowedHeaders Request headers allowed in CORS requests.
     * @param array<string> $exposedHeaders Response headers exposed to the browser.
     * @param int $maxAge How long preflight results can be cached (seconds).
     * @param bool $supportsCredentials Whether credentials are supported.
     */
    public function __construct(
        array $allowedOrigins = ['*'],
        array $allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        array $allowedHeaders = ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
        array $exposedHeaders = [],
        int $maxAge = 86400,
        bool $supportsCredentials = false,
    ) {
        $this->allowedOrigins = $allowedOrigins;
        $this->allowedMethods = array_map('strtoupper', $allowedMethods);
        $this->allowedHeaders = $allowedHeaders;
        $this->exposedHeaders = $exposedHeaders;
        $this->maxAge = $maxAge;
        $this->supportsCredentials = $supportsCredentials;
    }

    /**
     * Handle the incoming request.
     */
    public function handle(RequestInterface $req, ResponseInterface $res, callable $next): mixed
    {
        $origin = $req->header('Origin');

        // No Origin header = same-origin request, skip CORS handling
        if ($origin === null || $origin === '') {
            return $next($req, $res);
        }

        // Check if origin is allowed
        if (!$this->isOriginAllowed($origin)) {
            $res->json([
                'error' => 'CORS Error',
                'message' => 'Origin not allowed',
            ], 403);
            return null;
        }

        // Handle preflight OPTIONS request
        if ($req->method() === 'OPTIONS') {
            $this->handlePreflight($req, $res, $origin);
            return null;
        }

        // Add CORS headers to the response
        $this->addCorsHeaders($res, $origin);

        // Continue with the request
        return $next($req, $res);
    }

    /**
     * Check if the given origin is allowed.
     */
    private function isOriginAllowed(string $origin): bool
    {
        // Allow all origins
        if (in_array('*', $this->allowedOrigins, true)) {
            return true;
        }

        // Check exact match
        if (in_array($origin, $this->allowedOrigins, true)) {
            return true;
        }

        // Check wildcard patterns (e.g., '*.example.com')
        foreach ($this->allowedOrigins as $pattern) {
            if ($this->matchesWildcard($origin, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Match origin against a wildcard pattern.
     */
    private function matchesWildcard(string $origin, string $pattern): bool
    {
        if (!str_contains($pattern, '*')) {
            return false;
        }

        // Convert pattern to regex
        $regex = '/^' . str_replace(['.', '*'], ['\.', '.*'], $pattern) . '$/i';
        return (bool) preg_match($regex, $origin);
    }

    /**
     * Handle preflight OPTIONS request.
     */
    private function handlePreflight(RequestInterface $req, ResponseInterface $res, string $origin): void
    {
        // Validate requested method
        $requestedMethod = $req->header('Access-Control-Request-Method');
        if ($requestedMethod !== null && !in_array(strtoupper($requestedMethod), $this->allowedMethods, true)) {
            $res->json([
                'error' => 'CORS Error',
                'message' => 'Method not allowed',
            ], 403);
            return;
        }

        // Validate requested headers
        $requestedHeaders = $req->header('Access-Control-Request-Headers');
        if ($requestedHeaders !== null && !$this->areHeadersAllowed($requestedHeaders)) {
            $res->json([
                'error' => 'CORS Error',
                'message' => 'Headers not allowed',
            ], 403);
            return;
        }

        // Add preflight response headers
        $this->addCorsHeaders($res, $origin);
        $res->header('Access-Control-Max-Age', (string) $this->maxAge);

        // Return empty 204 response for preflight
        $res->noContent();
    }

    /**
     * Check if all requested headers are allowed.
     */
    private function areHeadersAllowed(string $requestedHeaders): bool
    {
        // Allow all headers if '*' is in allowedHeaders
        if (in_array('*', $this->allowedHeaders, true)) {
            return true;
        }

        $headers = array_map('trim', explode(',', $requestedHeaders));
        $allowedLower = array_map('strtolower', $this->allowedHeaders);

        foreach ($headers as $header) {
            if (!in_array(strtolower($header), $allowedLower, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Add CORS headers to the response.
     */
    private function addCorsHeaders(ResponseInterface $res, string $origin): void
    {
        // Set allowed origin
        if (in_array('*', $this->allowedOrigins, true) && !$this->supportsCredentials) {
            $res->header('Access-Control-Allow-Origin', '*');
        } else {
            $res->header('Access-Control-Allow-Origin', $origin);
            $res->header('Vary', 'Origin');
        }

        // Set allowed methods
        $res->header('Access-Control-Allow-Methods', implode(', ', $this->allowedMethods));

        // Set allowed headers
        if (!empty($this->allowedHeaders)) {
            $res->header('Access-Control-Allow-Headers', implode(', ', $this->allowedHeaders));
        }

        // Set exposed headers
        if (!empty($this->exposedHeaders)) {
            $res->header('Access-Control-Expose-Headers', implode(', ', $this->exposedHeaders));
        }

        // Set credentials support
        if ($this->supportsCredentials) {
            $res->header('Access-Control-Allow-Credentials', 'true');
        }
    }

    /**
     * Create middleware instance from configuration array.
     *
     * @param array<string, mixed> $config Configuration options
     * @return self
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            allowedOrigins: $config['allowed_origins'] ?? ['*'],
            allowedMethods: $config['allowed_methods'] ?? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
            allowedHeaders: $config['allowed_headers'] ?? ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
            exposedHeaders: $config['exposed_headers'] ?? [],
            maxAge: $config['max_age'] ?? 86400,
            supportsCredentials: $config['supports_credentials'] ?? false,
        );
    }

    /**
     * Create a permissive CORS middleware (allow everything).
     * Useful for development environments.
     *
     * @return self
     */
    public static function allowAll(): self
    {
        return new self(
            allowedOrigins: ['*'],
            allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
            allowedHeaders: ['*'],
            exposedHeaders: ['*'],
            maxAge: 86400,
            supportsCredentials: false,
        );
    }

    /**
     * Create a strict CORS middleware for production.
     *
     * @param array<string> $origins Allowed origins
     * @param bool $credentials Whether to support credentials
     * @return self
     */
    public static function strict(array $origins, bool $credentials = false): self
    {
        return new self(
            allowedOrigins: $origins,
            allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            exposedHeaders: [],
            maxAge: 3600,
            supportsCredentials: $credentials,
        );
    }
}
