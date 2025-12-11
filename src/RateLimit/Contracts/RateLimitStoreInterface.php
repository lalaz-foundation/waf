<?php

declare(strict_types=1);

namespace Lalaz\Waf\RateLimit\Contracts;

/**
 * Rate Limit Store Interface
 *
 * Defines the contract for persistent storage backends used by the rate limiter.
 * Implementations must provide persistent storage that survives between requests.
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 * @link https://lalaz.dev
 */
interface RateLimitStoreInterface
{
    /**
     * Get the token bucket data for a given key.
     *
     * @param string $key
     * @return array{tokens: float, last_refill: float}|null Array with bucket data, or null if not found
     */
    public function getBucket(string $key): ?array;

    /**
     * Save the token bucket data for a given key.
     *
     * @param string $key
     * @param array{tokens: float, last_refill: float} $bucket Array with 'tokens' and 'last_refill' keys
     * @param int $ttl Time to live in seconds
     * @return void
     */
    public function saveBucket(string $key, array $bucket, int $ttl): void;

    /**
     * Clear the rate limit data for a given key.
     *
     * @param string $key
     * @return void
     */
    public function clear(string $key): void;
}
