<?php

declare(strict_types=1);

namespace Lalaz\Waf\RateLimit\Stores;

use Lalaz\Waf\RateLimit\Contracts\RateLimitStoreInterface;

/**
 * Cache-Based Rate Limit Store
 *
 * Stores rate limit data using a PSR-compatible cache interface.
 * Works with Lalaz CacheManager or any cache implementing get/set/delete.
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 * @link https://lalaz.dev
 */
class CacheStore implements RateLimitStoreInterface
{
    /**
     * @var object Cache instance (CacheManager or similar)
     */
    private object $cache;

    /**
     * @var string Prefix for cache keys
     */
    private string $prefix;

    /**
     * Create a new CacheStore instance.
     *
     * @param object $cache Cache instance with get, set, delete methods
     * @param string $prefix Key prefix for rate limit entries
     */
    public function __construct(object $cache, string $prefix = 'rate_limit:')
    {
        $this->cache = $cache;
        $this->prefix = $prefix;
    }

    /**
     * {@inheritdoc}
     */
    public function getBucket(string $key): ?array
    {
        $cacheKey = $this->prefix . $key;

        // Try different cache interface methods
        if (method_exists($this->cache, 'get')) {
            $data = $this->cache->get($cacheKey);
        } elseif (method_exists($this->cache, 'fetch')) {
            $data = $this->cache->fetch($cacheKey);
        } else {
            throw new \RuntimeException('Cache instance must implement get() or fetch() method');
        }

        if ($data === null || $data === false) {
            return null;
        }

        // Handle serialized data
        if (is_string($data)) {
            $data = @unserialize($data);
        }

        if (!is_array($data) || !isset($data['tokens'], $data['last_refill'])) {
            return null;
        }

        return $data;
    }

    /**
     * {@inheritdoc}
     */
    public function saveBucket(string $key, array $bucket, int $ttl): void
    {
        $cacheKey = $this->prefix . $key;

        // Try different cache interface methods
        if (method_exists($this->cache, 'set')) {
            $this->cache->set($cacheKey, $bucket, $ttl);
        } elseif (method_exists($this->cache, 'put')) {
            $this->cache->put($cacheKey, $bucket, $ttl);
        } elseif (method_exists($this->cache, 'save')) {
            $this->cache->save($cacheKey, $bucket, $ttl);
        } else {
            throw new \RuntimeException('Cache instance must implement set(), put(), or save() method');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function clear(string $key): void
    {
        $cacheKey = $this->prefix . $key;

        // Try different cache interface methods
        if (method_exists($this->cache, 'delete')) {
            $this->cache->delete($cacheKey);
        } elseif (method_exists($this->cache, 'forget')) {
            $this->cache->forget($cacheKey);
        } elseif (method_exists($this->cache, 'remove')) {
            $this->cache->remove($cacheKey);
        } else {
            throw new \RuntimeException('Cache instance must implement delete(), forget(), or remove() method');
        }
    }
}
