# Rate Limiting

Request rate limiting with the token bucket algorithm.

---

## Overview

The rate limiting module provides protection against abuse by limiting the number of requests a client can make within a time window.

## Quick Start

```php
use Lalaz\Waf\RateLimit\RateLimiter;

$limiter = new RateLimiter();

$key = 'user:' . $userId;
$maxAttempts = 60;
$decaySeconds = 60;

if ($limiter->tooManyAttempts($key, $maxAttempts, $decaySeconds)) {
    $retryAfter = $limiter->availableIn($key);
    throw new TooManyRequestsException($retryAfter);
}

$limiter->hit($key, $decaySeconds);
```

## RateLimiter

### Constructor

```php
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\MemoryStore;
use Lalaz\Waf\RateLimit\Stores\RedisStore;

// Default (memory store)
$limiter = new RateLimiter();

// With custom store
$store = new RedisStore($redis, 'rate_limit:');
$limiter = new RateLimiter($store);
```

### Methods

#### `tooManyAttempts(string $key, int $maxAttempts, int $decaySeconds = 60): bool`

Check if the rate limit has been exceeded.

```php
if ($limiter->tooManyAttempts('api:user:123', 60, 60)) {
    // Rate limit exceeded
}
```

#### `hit(string $key, int $decaySeconds = 60): int`

Record a request attempt. Returns the new attempt count.

```php
$attempts = $limiter->hit('api:user:123', 60);
```

#### `remaining(string $key, int $maxAttempts, int $decaySeconds = 60): int`

Get the number of remaining attempts.

```php
$remaining = $limiter->remaining('api:user:123', 60, 60);
```

#### `availableIn(string $key): int`

Get the number of seconds until the rate limit resets.

```php
$retryAfter = $limiter->availableIn('api:user:123');
```

#### `resetAt(string $key): ?int`

Get the timestamp when the rate limit resets.

```php
$resetTimestamp = $limiter->resetAt('api:user:123');
```

#### `clear(string $key): void`

Clear the rate limit for a key.

```php
$limiter->clear('api:user:123');
```

## Storage Backends

### MemoryStore

In-memory storage. Best for testing and single-process applications.

```php
use Lalaz\Waf\RateLimit\Stores\MemoryStore;

$store = new MemoryStore();
$limiter = new RateLimiter($store);
```

### RedisStore

Redis-based storage. Best for distributed applications.

```php
use Lalaz\Waf\RateLimit\Stores\RedisStore;

// With Predis client
$redis = new \Predis\Client([
    'scheme' => 'tcp',
    'host'   => '127.0.0.1',
    'port'   => 6379,
]);

$store = new RedisStore($redis, 'rate_limit:');
$limiter = new RateLimiter($store);
```

### APCuStore

APCu-based storage. Best for single-server applications.

```php
use Lalaz\Waf\RateLimit\Stores\APCuStore;

$store = new APCuStore('rate_limit:');
$limiter = new RateLimiter($store);
```

### CacheStore

Integrates with any PSR-16 compatible cache.

```php
use Lalaz\Waf\RateLimit\Stores\CacheStore;

$store = new CacheStore($psr16Cache, 'rate_limit:');
$limiter = new RateLimiter($store);
```

## RateLimitStoreInterface

Create custom storage backends by implementing `RateLimitStoreInterface`:

```php
use Lalaz\Waf\RateLimit\Contracts\RateLimitStoreInterface;

class DatabaseStore implements RateLimitStoreInterface
{
    public function get(string $key): ?array
    {
        // Return ['attempts' => int, 'reset_at' => int] or null
    }
    
    public function set(string $key, int $attempts, int $decaySeconds): void
    {
        // Store the rate limit data
    }
    
    public function increment(string $key, int $decaySeconds): int
    {
        // Increment and return new count
    }
    
    public function clear(string $key): void
    {
        // Remove the rate limit data
    }
}
```

## RateLimitMiddleware

Use the middleware for automatic rate limiting:

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;

// 60 requests per minute
$middleware = RateLimitMiddleware::perMinute(60);

// 1000 requests per hour
$middleware = RateLimitMiddleware::perHour(1000);

// 10000 requests per day
$middleware = RateLimitMiddleware::perDay(10000);

// Login attempts (5 per minute)
$middleware = RateLimitMiddleware::forLogin();

// API rate limiting (100 per minute)
$middleware = RateLimitMiddleware::forApi();
```

### Custom Configuration

```php
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\RedisStore;

$store = new RedisStore($redis);
$limiter = new RateLimiter($store);

$middleware = new RateLimitMiddleware(
    limiter: $limiter,
    maxAttempts: 100,
    decaySeconds: 300,
    keyResolver: fn($request) => 'api:' . $request->getAttribute('user_id')
);
```

## Exception Handling

```php
use Lalaz\Waf\RateLimit\RateLimitExceededException;

try {
    if ($limiter->tooManyAttempts($key, 60, 60)) {
        throw new RateLimitExceededException(
            $limiter->availableIn($key)
        );
    }
} catch (RateLimitExceededException $e) {
    return response()
        ->withStatus(429)
        ->withHeader('Retry-After', $e->retryAfter);
}
```

## Best Practices

1. **Use appropriate key prefixes** to avoid collisions
2. **Choose the right storage backend** for your deployment
3. **Set reasonable limits** based on your application's needs
4. **Include Retry-After headers** in rate limit responses
5. **Monitor rate limit hits** to detect abuse patterns

## Next Steps

- [Threat Detection](../detection/index.md) — Detect malicious input
- [IP Filtering](../ip-filter/index.md) — Filter by IP address
- [Middlewares](../middlewares/index.md) — All available middlewares
