<?php

declare(strict_types=1);

namespace Lalaz\Waf\RateLimit;

use Lalaz\Waf\RateLimit\Contracts\RateLimitStoreInterface;

/**
 * Rate Limiter
 *
 * Implements the Token Bucket algorithm for rate limiting.
 * Supports pluggable storage backends for different environments.
 *
 * The Token Bucket algorithm works by:
 * 1. Each bucket has a maximum number of tokens
 * 2. Tokens are consumed with each request
 * 3. Tokens refill at a steady rate over time
 * 4. If no tokens are available, the request is rate limited
 *
 * @example Basic usage:
 * ```php
 * $limiter = new RateLimiter(new CacheStore($cache));
 *
 * $key = 'api:user:123';
 * if ($limiter->tooManyAttempts($key, maxAttempts: 100, decayMinutes: 1)) {
 *     throw new RateLimitExceededException('Rate limit exceeded');
 * }
 *
 * $limiter->hit($key, 100, 1);
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 * @link https://lalaz.dev
 */
class RateLimiter
{
    /**
     * @var RateLimitStoreInterface Storage backend
     */
    private RateLimitStoreInterface $store;

    /**
     * Create a new RateLimiter instance.
     *
     * @param RateLimitStoreInterface $store Storage backend for rate limit data
     */
    public function __construct(RateLimitStoreInterface $store)
    {
        $this->store = $store;
    }

    /**
     * Check if too many attempts have been made.
     *
     * @param string $key Unique identifier (e.g., "login:127.0.0.1")
     * @param int $maxAttempts Maximum number of attempts allowed
     * @param int $decayMinutes Time window in minutes
     * @return bool True if rate limit exceeded
     */
    public function tooManyAttempts(
        string $key,
        int $maxAttempts,
        int $decayMinutes = 1,
    ): bool {
        $bucket = $this->getBucket($key, $maxAttempts);
        $this->refillTokens($bucket, $maxAttempts, $decayMinutes);

        // Persist the refreshed bucket
        $this->store->saveBucket($key, $bucket, $decayMinutes * 60);

        return $bucket['tokens'] < 1;
    }

    /**
     * Increment the counter for a given key (consume a token).
     *
     * @param string $key Unique identifier
     * @param int $maxAttempts Maximum number of attempts allowed
     * @param int $decayMinutes Number of minutes until the limit resets
     * @return int Remaining tokens
     */
    public function hit(
        string $key,
        int $maxAttempts,
        int $decayMinutes = 1,
    ): int {
        $bucket = $this->getBucket($key, $maxAttempts);
        $this->refillTokens($bucket, $maxAttempts, $decayMinutes);

        // Consume one token
        $bucket['tokens'] = max(0, $bucket['tokens'] - 1);

        // Save bucket
        $this->store->saveBucket($key, $bucket, $decayMinutes * 60);

        return (int) max(0, floor($bucket['tokens']));
    }

    /**
     * Get the number of attempts remaining.
     *
     * @param string $key
     * @param int $maxAttempts
     * @param int $decayMinutes
     * @return int
     */
    public function remaining(
        string $key,
        int $maxAttempts,
        int $decayMinutes = 1,
    ): int {
        $bucket = $this->getBucket($key, $maxAttempts);
        $this->refillTokens($bucket, $maxAttempts, $decayMinutes);

        // Persist refreshed bucket
        $this->store->saveBucket($key, $bucket, $decayMinutes * 60);

        return (int) max(0, floor($bucket['tokens']));
    }

    /**
     * Get the number of seconds until the rate limit resets.
     *
     * @param string $key
     * @param int $maxAttempts
     * @param int $decayMinutes
     * @return int Seconds until next token available
     */
    public function availableIn(
        string $key,
        int $maxAttempts,
        int $decayMinutes = 1,
    ): int {
        $bucket = $this->getBucket($key, $maxAttempts);
        $this->refillTokens($bucket, $maxAttempts, $decayMinutes);

        // Persist bucket
        $this->store->saveBucket($key, $bucket, $decayMinutes * 60);

        $now = microtime(true);
        $tokens = $bucket['tokens'] ?? 0;

        // If we have tokens, available immediately
        if ($tokens >= 1) {
            return 0;
        }

        // Calculate time needed to get 1 token
        $refillRate = $maxAttempts / ($decayMinutes * 60); // tokens per second
        $tokensNeeded = 1 - $tokens;
        $secondsNeeded = (int) ceil($tokensNeeded / max($refillRate, 0.000001));

        // Clamp to decay window
        $maxWindowSeconds = $decayMinutes * 60;
        $lastRefill = $bucket['last_refill'] ?? $now;
        $elapsedSinceLastRefill = (int) ceil($now - $lastRefill);

        return (int) max(
            0,
            min(
                $secondsNeeded,
                max(0, $maxWindowSeconds - $elapsedSinceLastRefill),
            ),
        );
    }

    /**
     * Get the timestamp when the rate limit resets.
     *
     * @param string $key
     * @param int $decayMinutes
     * @return int Unix timestamp
     */
    public function resetAt(string $key, int $decayMinutes): int
    {
        $bucket = $this->store->getBucket($key);

        if ($bucket === null) {
            return time() + $decayMinutes * 60;
        }

        $lastRefill = $bucket['last_refill'] ?? microtime(true);
        return (int) ($lastRefill + $decayMinutes * 60);
    }

    /**
     * Clear the rate limiter for a given key.
     *
     * @param string $key
     * @return void
     */
    public function clear(string $key): void
    {
        $this->store->clear($key);
    }

    /**
     * Get or create a token bucket for the given key.
     *
     * @param string $key
     * @param int $maxTokens
     * @return array{tokens: float, last_refill: float}
     */
    private function getBucket(string $key, int $maxTokens): array
    {
        $bucket = $this->store->getBucket($key);

        if ($bucket === null) {
            // Initialize new bucket with full tokens
            return [
                'tokens' => (float) $maxTokens,
                'last_refill' => microtime(true),
            ];
        }

        return $bucket;
    }

    /**
     * Refill tokens based on elapsed time (Token Bucket algorithm).
     *
     * @param array{tokens: float, last_refill: float} &$bucket
     * @param int $maxTokens
     * @param int $decayMinutes
     * @return void
     */
    private function refillTokens(array &$bucket, int $maxTokens, int $decayMinutes): void
    {
        $now = microtime(true);
        $lastRefill = $bucket['last_refill'] ?? $now;
        $elapsed = $now - $lastRefill;

        if ($elapsed <= 0) {
            return;
        }

        // Refill rate: maxTokens per decay window
        $windowSeconds = $decayMinutes * 60;
        $refillRate = $maxTokens / $windowSeconds; // tokens per second
        $tokensToAdd = $elapsed * $refillRate;

        // Add tokens, capped at maxTokens
        $bucket['tokens'] = min(
            $maxTokens,
            ($bucket['tokens'] ?? 0) + $tokensToAdd,
        );
        $bucket['last_refill'] = $now;
    }
}
