<?php

declare(strict_types=1);

namespace Lalaz\Waf\RateLimit\Stores;

use Lalaz\Waf\RateLimit\Contracts\RateLimitStoreInterface;

/**
 * APCu-based Rate Limit Store
 *
 * Uses APCu (Alternative PHP Cache User) for persistent storage.
 * Works well for single-server setups but does not support clustering.
 *
 * APCu stores data in shared memory, making it extremely fast for
 * single-server deployments. However, data is not shared across
 * multiple servers, so use Redis or another distributed store
 * for clustered environments.
 *
 * @example Basic usage:
 * ```php
 * $store = new APCuStore();
 * $limiter = new RateLimiter($store);
 * ```
 *
 * @example With custom prefix:
 * ```php
 * $store = new APCuStore('myapp:ratelimit:');
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 * @link https://lalaz.dev
 */
class APCuStore implements RateLimitStoreInterface
{
    /**
     * Key prefix for namespacing.
     */
    private string $prefix;

    /**
     * Create a new APCu store instance.
     *
     * @param string $prefix Optional key prefix for namespacing
     * @throws \RuntimeException If APCu extension is not available
     */
    public function __construct(string $prefix = 'rl:')
    {
        if (!extension_loaded('apcu')) {
            throw new \RuntimeException(
                'APCu extension is not loaded. Install with: pecl install apcu'
            );
        }

        if (!apcu_enabled()) {
            throw new \RuntimeException(
                'APCu is loaded but not enabled. Check your php.ini configuration. ' .
                'For CLI, ensure apc.enable_cli=1 is set.'
            );
        }

        $this->prefix = $prefix;
    }

    /**
     * {@inheritDoc}
     */
    public function getBucket(string $key): ?array
    {
        $data = apcu_fetch($this->prefix . $key, $success);

        if (!$success) {
            return null;
        }

        return is_array($data) ? $data : null;
    }

    /**
     * {@inheritDoc}
     */
    public function saveBucket(string $key, array $bucket, int $ttl): void
    {
        apcu_store($this->prefix . $key, $bucket, $ttl);
    }

    /**
     * {@inheritDoc}
     */
    public function clear(string $key): void
    {
        apcu_delete($this->prefix . $key);
    }

    /**
     * Clear all rate limit data from APCu.
     *
     * Warning: This will clear ALL keys with the configured prefix.
     *
     * @return void
     */
    public function clearAll(): void
    {
        $iterator = new \APCUIterator(
            '/^' . preg_quote($this->prefix, '/') . '/',
            APC_ITER_KEY
        );

        foreach ($iterator as $item) {
            apcu_delete($item['key']);
        }
    }

    /**
     * Check if APCu is available and enabled.
     *
     * @return bool
     */
    public static function isAvailable(): bool
    {
        return extension_loaded('apcu') && apcu_enabled();
    }

    /**
     * Get APCu cache info for debugging.
     *
     * @return array{num_slots: int, num_hits: int, num_misses: int, num_entries: int, mem_size: int}|null
     */
    public function getInfo(): ?array
    {
        $info = apcu_cache_info(true);

        if ($info === false) {
            return null;
        }

        return [
            'num_slots' => $info['num_slots'] ?? 0,
            'num_hits' => $info['num_hits'] ?? 0,
            'num_misses' => $info['num_misses'] ?? 0,
            'num_entries' => $info['num_entries'] ?? 0,
            'mem_size' => $info['mem_size'] ?? 0,
        ];
    }
}
