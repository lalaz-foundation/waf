# Installation

How to install and configure the WAF package.

---

## Requirements

- PHP 8.2 or higher
- Composer
- PSR-7 compatible HTTP library
- PSR-15 compatible middleware dispatcher

## Install via Composer

```bash
composer require lalaz/waf
```

## Optional Dependencies

### Redis (for distributed rate limiting)

```bash
composer require predis/predis
# or
pecl install redis
```

### APCu (for single-server rate limiting)

```bash
pecl install apcu
```

### MaxMind GeoIP (for geo blocking)

```bash
composer require geoip2/geoip2
```

## Configuration

### Rate Limit Store

By default, WAF uses in-memory storage for rate limiting. For production, use Redis or APCu:

```php
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\RedisStore;
use Lalaz\Waf\RateLimit\Stores\APCuStore;

// Redis store (distributed)
$store = new RedisStore($redisClient, 'rate_limit:');
$limiter = new RateLimiter($store);

// APCu store (single server)
$store = new APCuStore('rate_limit:');
$limiter = new RateLimiter($store);
```

### Geo Provider

Configure a geo provider for geo blocking:

```php
use Lalaz\Waf\Geo\Providers\ArrayGeoProvider;
use Lalaz\Waf\Geo\GeoLocation;

// Simple array provider (for testing)
$provider = new ArrayGeoProvider([
    '8.8.8.8' => GeoLocation::create([
        'country' => 'US',
        'countryName' => 'United States',
    ]),
]);

// MaxMind provider (production)
// Requires geoip2/geoip2 package
$provider = new MaxMindGeoProvider('/path/to/GeoLite2-City.mmdb');
```

## Framework Integration

### Lalaz Framework

```php
// config/waf.php
return [
    'rate_limit' => [
        'driver' => 'redis', // memory, redis, apcu
        'default_limit' => 60,
        'default_window' => 60,
    ],
    
    'detection' => [
        'enabled' => true,
        'types' => ['xss', 'sql_injection', 'path_traversal', 'command_injection'],
        'mode' => 'block', // block, log
    ],
    
    'cors' => [
        'origins' => ['*'],
        'methods' => ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        'headers' => ['Content-Type', 'Authorization'],
    ],
    
    'geo' => [
        'provider' => 'maxmind',
        'database' => storage_path('geo/GeoLite2-City.mmdb'),
    ],
];
```

### PSR-15 Middleware Stack

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;

$middlewareDispatcher->add(RateLimitMiddleware::perMinute(60));
$middlewareDispatcher->add(SanitizationMiddleware::strict());
```

## Verification

Verify the installation:

```php
use Lalaz\Waf\Detection\ThreatDetector;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\IpFilter\IpMatcher;

// Test threat detection
$detector = ThreatDetector::all();
$threats = $detector->scan('<script>alert("xss")</script>');
var_dump($threats); // Should detect XSS

// Test rate limiter
$limiter = new RateLimiter();
$result = $limiter->tooManyAttempts('test:key', 5, 60);
var_dump($result); // false

// Test IP matcher
$matches = IpMatcher::matches('192.168.1.100', '192.168.1.0/24');
var_dump($matches); // true
```

## Next Steps

- [Quick Start](quick-start.md) — Get started in 5 minutes
- [Concepts](concepts.md) — Understand the architecture
- [API Reference](api-reference.md) — Complete API documentation
