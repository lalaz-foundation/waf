<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\RateLimitExceededException;
use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * Rate Limit Middleware
 *
 * Applies rate limiting to routes based on configurable rules.
 * Supports different key strategies: IP, user, route, or custom closure.
 *
 * @example Basic usage - 60 requests per minute by IP:
 * ```php
 * $router->middleware(new RateLimitMiddleware(60, 1));
 * ```
 *
 * @example Per-user rate limiting:
 * ```php
 * $router->middleware(new RateLimitMiddleware(100, 1, 'user'));
 * ```
 *
 * @example Custom key resolution:
 * ```php
 * $router->middleware(new RateLimitMiddleware(
 *     maxAttempts: 10,
 *     decayMinutes: 1,
 *     keyResolver: fn($req) => 'api:' . $req->header('X-API-Key'),
 * ));
 * ```
 *
 * @example Using factory methods:
 * ```php
 * $router->middleware(RateLimitMiddleware::perMinute(60));
 * $router->middleware(RateLimitMiddleware::perHour(1000));
 * $router->middleware(RateLimitMiddleware::perDay(10000));
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 * @link https://lalaz.dev
 */
class RateLimitMiddleware implements MiddlewareInterface
{
    /**
     * @var RateLimiter|null Rate limiter instance (lazy loaded)
     */
    private ?RateLimiter $limiter = null;

    /**
     * @var int Maximum number of requests allowed
     */
    private int $maxAttempts;

    /**
     * @var int Time window in minutes
     */
    private int $decayMinutes;

    /**
     * @var string|\Closure Key resolution strategy
     */
    private string|\Closure $keyResolver;

    /**
     * @var bool Whether to throw exception or return response
     */
    private bool $throwOnLimit;

    /**
     * @var array<string, mixed> Custom response data when rate limited
     */
    private array $limitResponse;

    /**
     * Create a new RateLimitMiddleware instance.
     *
     * @param int $maxAttempts Maximum number of requests allowed
     * @param int $decayMinutes Time window in minutes
     * @param string|\Closure $keyResolver Key resolution: 'ip', 'user', 'route', or custom closure
     * @param bool $throwOnLimit Whether to throw exception instead of returning response
     * @param array<string, mixed> $limitResponse Custom response when rate limited
     */
    public function __construct(
        int $maxAttempts = 60,
        int $decayMinutes = 1,
        string|\Closure $keyResolver = 'ip',
        bool $throwOnLimit = false,
        array $limitResponse = [],
    ) {
        $this->maxAttempts = $maxAttempts;
        $this->decayMinutes = $decayMinutes;
        $this->keyResolver = $keyResolver;
        $this->throwOnLimit = $throwOnLimit;
        $this->limitResponse = $limitResponse;
    }

    /**
     * Handle the incoming request.
     */
    public function handle(RequestInterface $req, ResponseInterface $res, callable $next): mixed
    {
        // Lazy load limiter
        if ($this->limiter === null) {
            $this->limiter = $this->resolveLimiter();
        }

        $key = $this->resolveKey($req);

        // Check if rate limit exceeded
        if ($this->limiter->tooManyAttempts($key, $this->maxAttempts, $this->decayMinutes)) {
            $this->handleRateLimitExceeded($req, $res, $key);
            return null;
        }

        // Consume a token
        $this->limiter->hit($key, $this->maxAttempts, $this->decayMinutes);

        // Add rate limit headers to response
        $this->addRateLimitHeaders($res, $key);

        // Continue with the request
        return $next($req, $res);
    }

    /**
     * Resolve the rate limiter instance.
     */
    private function resolveLimiter(): RateLimiter
    {
        // Try to resolve from container
        if (function_exists('resolve')) {
            try {
                return resolve(RateLimiter::class);
            } catch (\Throwable) {
                // Fall through to create default
            }
        }

        // Create default limiter with memory store
        $store = new \Lalaz\Waf\RateLimit\Stores\MemoryStore();
        return new RateLimiter($store);
    }

    /**
     * Resolve the rate limit key based on the request.
     */
    private function resolveKey(RequestInterface $req): string
    {
        // Custom closure
        if ($this->keyResolver instanceof \Closure) {
            return 'rl:' . ($this->keyResolver)($req);
        }

        // Predefined key types
        return match ($this->keyResolver) {
            'ip' => 'rl:ip:' . $req->ip(),
            'user' => 'rl:user:' . $this->resolveUserId($req),
            'route' => 'rl:route:' . $req->method() . ':' . $req->path() . ':' . $req->ip(),
            default => 'rl:ip:' . $req->ip(),
        };
    }

    /**
     * Resolve the user ID from the request.
     */
    private function resolveUserId(RequestInterface $req): string
    {
        // Try to get user from request
        if (method_exists($req, 'user')) {
            $user = $req->user();
            if ($user !== null) {
                return $this->extractUserId($user);
            }
        }

        // Try auth context
        if (function_exists('resolve')) {
            try {
                $auth = resolve('Lalaz\Auth\AuthContext');
                if (method_exists($auth, 'id') && $auth->id() !== null) {
                    return (string) $auth->id();
                }
            } catch (\Throwable) {
                // Fall through
            }
        }

        // Fall back to IP-based
        return 'guest:' . $req->ip();
    }

    /**
     * Extract user ID from user object.
     */
    private function extractUserId(mixed $user): string
    {
        if (is_string($user) || is_numeric($user)) {
            return (string) $user;
        }

        if (is_array($user) && isset($user['id'])) {
            return (string) $user['id'];
        }

        if (is_object($user)) {
            if (isset($user->id)) {
                return (string) $user->id;
            }

            if (method_exists($user, 'getId')) {
                return (string) $user->getId();
            }
        }

        return 'unknown';
    }

    /**
     * Handle rate limit exceeded.
     */
    private function handleRateLimitExceeded(RequestInterface $req, ResponseInterface $res, string $key): void
    {
        $retryAfter = $this->limiter->availableIn($key, $this->maxAttempts, $this->decayMinutes);
        $resetAt = $this->limiter->resetAt($key, $this->decayMinutes);

        // Throw exception if configured
        if ($this->throwOnLimit) {
            throw new RateLimitExceededException(
                'Rate limit exceeded. Please try again in ' . $retryAfter . ' seconds.',
                $retryAfter,
                $this->maxAttempts,
            );
        }

        // Build response
        $responseData = array_merge([
            'error' => 'Too Many Requests',
            'message' => "Rate limit exceeded. Please try again in {$retryAfter} seconds.",
            'retry_after' => $retryAfter,
        ], $this->limitResponse);

        $res->header('Retry-After', (string) $retryAfter)
            ->header('X-RateLimit-Limit', (string) $this->maxAttempts)
            ->header('X-RateLimit-Remaining', '0')
            ->header('X-RateLimit-Reset', (string) $resetAt)
            ->json($responseData, 429);
    }

    /**
     * Add rate limit headers to the response.
     */
    private function addRateLimitHeaders(ResponseInterface $res, string $key): void
    {
        $remaining = $this->limiter->remaining($key, $this->maxAttempts, $this->decayMinutes);
        $resetAt = $this->limiter->resetAt($key, $this->decayMinutes);

        $res->header('X-RateLimit-Limit', (string) $this->maxAttempts)
            ->header('X-RateLimit-Remaining', (string) $remaining)
            ->header('X-RateLimit-Reset', (string) $resetAt);
    }

    /**
     * Set the rate limiter instance (for testing or custom configuration).
     *
     * @param RateLimiter $limiter
     * @return self
     */
    public function withLimiter(RateLimiter $limiter): self
    {
        $clone = clone $this;
        $clone->limiter = $limiter;
        return $clone;
    }

    /**
     * Create middleware instance from configuration array.
     *
     * @param array<string, mixed> $config
     * @return self
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            maxAttempts: $config['max_attempts'] ?? 60,
            decayMinutes: $config['decay_minutes'] ?? 1,
            keyResolver: $config['key'] ?? 'ip',
            throwOnLimit: $config['throw_on_limit'] ?? false,
            limitResponse: $config['limit_response'] ?? [],
        );
    }

    /**
     * Create a rate limiter for X requests per minute.
     *
     * @param int $requests
     * @param string|\Closure $keyResolver
     * @return self
     */
    public static function perMinute(int $requests, string|\Closure $keyResolver = 'ip'): self
    {
        return new self(
            maxAttempts: $requests,
            decayMinutes: 1,
            keyResolver: $keyResolver,
        );
    }

    /**
     * Create a rate limiter for X requests per hour.
     *
     * @param int $requests
     * @param string|\Closure $keyResolver
     * @return self
     */
    public static function perHour(int $requests, string|\Closure $keyResolver = 'ip'): self
    {
        return new self(
            maxAttempts: $requests,
            decayMinutes: 60,
            keyResolver: $keyResolver,
        );
    }

    /**
     * Create a rate limiter for X requests per day.
     *
     * @param int $requests
     * @param string|\Closure $keyResolver
     * @return self
     */
    public static function perDay(int $requests, string|\Closure $keyResolver = 'ip'): self
    {
        return new self(
            maxAttempts: $requests,
            decayMinutes: 1440,
            keyResolver: $keyResolver,
        );
    }

    /**
     * Create a strict rate limiter for sensitive endpoints (e.g., login).
     *
     * @param int $attempts Maximum login attempts
     * @param int $lockoutMinutes Lockout duration
     * @return self
     */
    public static function forLogin(int $attempts = 5, int $lockoutMinutes = 15): self
    {
        return new self(
            maxAttempts: $attempts,
            decayMinutes: $lockoutMinutes,
            keyResolver: 'ip',
            throwOnLimit: false,
            limitResponse: [
                'error' => 'Too Many Login Attempts',
                'message' => 'Your account has been temporarily locked due to too many failed login attempts.',
            ],
        );
    }

    /**
     * Create a rate limiter for API endpoints.
     *
     * @param int $requestsPerMinute
     * @return self
     */
    public static function forApi(int $requestsPerMinute = 60): self
    {
        return new self(
            maxAttempts: $requestsPerMinute,
            decayMinutes: 1,
            keyResolver: fn ($req) => $req->header('Authorization') ?? $req->header('X-API-Key') ?? $req->ip(),
        );
    }
}
