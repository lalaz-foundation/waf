<?php

declare(strict_types=1);

namespace Lalaz\Waf\RateLimit\Stores;

use Lalaz\Waf\RateLimit\Contracts\RateLimitStoreInterface;

/**
 * In-Memory Rate Limit Store
 *
 * Stores rate limit data in memory (static array).
 * Useful for testing or single-request scenarios.
 * NOT suitable for production use in multi-process environments.
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 * @link https://lalaz.dev
 */
class MemoryStore implements RateLimitStoreInterface
{
    /**
     * @var array<string, array{bucket: array{tokens: float, last_refill: float}, expires: int}>
     */
    private static array $buckets = [];

    /**
     * {@inheritdoc}
     */
    public function getBucket(string $key): ?array
    {
        $this->cleanExpired();

        if (!isset(self::$buckets[$key])) {
            return null;
        }

        $data = self::$buckets[$key];

        // Check if expired
        if ($data['expires'] < time()) {
            unset(self::$buckets[$key]);
            return null;
        }

        return $data['bucket'];
    }

    /**
     * {@inheritdoc}
     */
    public function saveBucket(string $key, array $bucket, int $ttl): void
    {
        self::$buckets[$key] = [
            'bucket' => $bucket,
            'expires' => time() + $ttl,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function clear(string $key): void
    {
        unset(self::$buckets[$key]);
    }

    /**
     * Clear all stored buckets.
     *
     * @return void
     */
    public function clearAll(): void
    {
        self::$buckets = [];
    }

    /**
     * Clean expired entries.
     *
     * @return void
     */
    private function cleanExpired(): void
    {
        $now = time();

        foreach (self::$buckets as $key => $data) {
            if ($data['expires'] < $now) {
                unset(self::$buckets[$key]);
            }
        }
    }
}
