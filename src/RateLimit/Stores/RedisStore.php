<?php

declare(strict_types=1);

namespace Lalaz\Waf\RateLimit\Stores;

use Lalaz\Waf\RateLimit\Contracts\RateLimitStoreInterface;

/**
 * Redis-based Rate Limit Store
 *
 * Supports both phpredis extension and predis/predis package.
 * Provides high-performance persistent storage for rate limiting
 * that works across multiple servers in a cluster.
 *
 * Redis is the recommended store for production environments,
 * especially when running multiple application servers.
 *
 * @example Using phpredis extension:
 * ```php
 * $store = new RedisStore([
 *     'host' => '127.0.0.1',
 *     'port' => 6379,
 *     'password' => 'secret',
 *     'database' => 0,
 * ]);
 * $limiter = new RateLimiter($store);
 * ```
 *
 * @example Using existing Redis connection:
 * ```php
 * $redis = new \Redis();
 * $redis->connect('127.0.0.1', 6379);
 * $store = RedisStore::fromConnection($redis);
 * ```
 *
 * @example Using Predis client:
 * ```php
 * $predis = new \Predis\Client(['host' => '127.0.0.1']);
 * $store = RedisStore::fromConnection($predis);
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 * @link https://lalaz.dev
 */
class RedisStore implements RateLimitStoreInterface
{
    /**
     * Redis client instance (phpredis or Predis).
     *
     * @var \Redis|\Predis\Client|object
     */
    private object $redis;

    /**
     * Key prefix for namespacing.
     */
    private string $prefix;

    /**
     * Create a new Redis store instance.
     *
     * @param array<string, mixed> $config Connection configuration
     * @param string $prefix Optional key prefix for namespacing
     * @throws \RuntimeException If Redis is not available
     */
    public function __construct(array $config = [], string $prefix = 'rl:')
    {
        $this->prefix = $prefix;
        $this->redis = $this->createConnection($config);
    }

    /**
     * Create a store from an existing Redis connection.
     *
     * @param \Redis|\Predis\Client $connection Existing Redis connection
     * @param string $prefix Optional key prefix
     * @return self
     */
    public static function fromConnection(object $connection, string $prefix = 'rl:'): self
    {
        $instance = new self([], $prefix);
        $instance->redis = $connection;
        return $instance;
    }

    /**
     * Create Redis connection based on available driver.
     *
     * @param array<string, mixed> $config
     * @return \Redis|object
     * @throws \RuntimeException
     */
    private function createConnection(array $config): object
    {
        // Try phpredis extension first (fastest)
        if (extension_loaded('redis')) {
            return $this->createPhpRedisConnection($config);
        }

        // Fallback to predis package
        if (class_exists(\Predis\Client::class)) {
            return $this->createPredisConnection($config);
        }

        throw new \RuntimeException(
            "Redis support requires either phpredis extension or predis/predis package.\n" .
            'Install with: pecl install redis OR composer require predis/predis'
        );
    }

    /**
     * Create connection using phpredis extension.
     *
     * @param array<string, mixed> $config
     * @return \Redis
     */
    private function createPhpRedisConnection(array $config): \Redis
    {
        $redis = new \Redis();

        $host = $config['host'] ?? $config['REDIS_HOST'] ?? '127.0.0.1';
        $port = (int) ($config['port'] ?? $config['REDIS_PORT'] ?? 6379);
        $timeout = (float) ($config['timeout'] ?? 0.0);

        $redis->connect($host, $port, $timeout);

        $password = $config['password'] ?? $config['REDIS_PASSWORD'] ?? null;
        if (!empty($password)) {
            $redis->auth($password);
        }

        $database = $config['database'] ?? $config['REDIS_DATABASE'] ?? null;
        if ($database !== null) {
            $redis->select((int) $database);
        }

        return $redis;
    }

    /**
     * Create connection using predis package.
     *
     * @param array<string, mixed> $config
     * @return \Predis\Client
     */
    private function createPredisConnection(array $config): object
    {
        return new \Predis\Client([
            'scheme' => $config['scheme'] ?? 'tcp',
            'host' => $config['host'] ?? $config['REDIS_HOST'] ?? '127.0.0.1',
            'port' => (int) ($config['port'] ?? $config['REDIS_PORT'] ?? 6379),
            'password' => $config['password'] ?? $config['REDIS_PASSWORD'] ?? null,
            'database' => (int) ($config['database'] ?? $config['REDIS_DATABASE'] ?? 0),
        ]);
    }

    /**
     * {@inheritDoc}
     */
    public function getBucket(string $key): ?array
    {
        $data = $this->redis->get($this->prefix . $key);

        if ($data === false || $data === null) {
            return null;
        }

        $decoded = json_decode($data, true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * {@inheritDoc}
     */
    public function saveBucket(string $key, array $bucket, int $ttl): void
    {
        $this->redis->setex(
            $this->prefix . $key,
            $ttl,
            json_encode($bucket, JSON_THROW_ON_ERROR)
        );
    }

    /**
     * {@inheritDoc}
     */
    public function clear(string $key): void
    {
        $this->redis->del($this->prefix . $key);
    }

    /**
     * Clear all rate limit data from Redis.
     *
     * Warning: This uses SCAN to find keys, which may be slow on large datasets.
     *
     * @return int Number of keys deleted
     */
    public function clearAll(): int
    {
        $pattern = $this->prefix . '*';
        $deleted = 0;

        if ($this->redis instanceof \Redis) {
            $iterator = null;
            while ($keys = $this->redis->scan($iterator, $pattern, 100)) {
                if (!empty($keys)) {
                    $deleted += $this->redis->del($keys);
                }
            }
        } else {
            // Predis
            $iterator = new \Predis\Collection\Iterator\Keyspace($this->redis, $pattern);
            $keys = [];
            foreach ($iterator as $key) {
                $keys[] = $key;
                if (count($keys) >= 100) {
                    $deleted += count($keys);
                    $this->redis->del($keys);
                    $keys = [];
                }
            }
            if (!empty($keys)) {
                $deleted += count($keys);
                $this->redis->del($keys);
            }
        }

        return $deleted;
    }

    /**
     * Check if Redis is available.
     *
     * @return bool
     */
    public static function isAvailable(): bool
    {
        return extension_loaded('redis') || class_exists(\Predis\Client::class);
    }

    /**
     * Get the underlying Redis client.
     *
     * @return \Redis|\Predis\Client
     */
    public function getClient(): object
    {
        return $this->redis;
    }

    /**
     * Ping Redis to check connection.
     *
     * @return bool
     */
    public function ping(): bool
    {
        try {
            $result = $this->redis->ping();
            return $result === true || $result === '+PONG' || $result === 'PONG';
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Get Redis info for debugging.
     *
     * @param string|null $section Specific section to retrieve
     * @return array<string, mixed>|null
     */
    public function getInfo(?string $section = null): ?array
    {
        try {
            if ($section !== null) {
                $info = $this->redis->info($section);
            } else {
                $info = $this->redis->info();
            }
            return is_array($info) ? $info : null;
        } catch (\Throwable) {
            return null;
        }
    }
}
