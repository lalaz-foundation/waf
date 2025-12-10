# Quick Start

Get started with WAF in 5 minutes.

---

## 1. Install the Package

```bash
composer require lalaz/waf
```

## 2. Basic Rate Limiting

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;

// 60 requests per minute
$router->middleware(RateLimitMiddleware::perMinute(60));

// 1000 requests per hour
$router->middleware(RateLimitMiddleware::perHour(1000));

// Custom: 100 requests per 5 minutes
$router->middleware(RateLimitMiddleware::perMinute(100, 5));
```

## 3. Threat Detection

```php
use Lalaz\Waf\Middlewares\SanitizationMiddleware;

// Block all detected threats
$router->middleware(SanitizationMiddleware::strict());

// Log threats only (don't block)
$router->middleware(SanitizationMiddleware::logOnly());

// Basic sanitization
$router->middleware(SanitizationMiddleware::basic());
```

## 4. CORS

```php
use Lalaz\Waf\Middlewares\CorsMiddleware;

// Allow all origins (development)
$router->middleware(CorsMiddleware::allowAll());

// Strict mode with specific origin
$router->middleware(CorsMiddleware::strict('https://example.com'));
```

## 5. Security Headers

```php
use Lalaz\Waf\Middlewares\HelmetMiddleware;

// Production-ready strict headers
$router->middleware(HelmetMiddleware::strict());

// Development mode (relaxed)
$router->middleware(HelmetMiddleware::development());

// API mode
$router->middleware(HelmetMiddleware::api());
```

## 6. IP Filtering

```php
use Lalaz\Waf\Middlewares\IpFilterMiddleware;

// Allow only specific IPs
$router->middleware(IpFilterMiddleware::whitelist(['192.168.1.0/24']));

// Block specific IPs
$router->middleware(IpFilterMiddleware::blacklist(['10.0.0.1']));

// Internal only
$router->middleware(IpFilterMiddleware::internalOnly());
```

## 7. Geo Blocking

```php
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;

// Allow only US and Canada
$router->middleware(GeoBlockMiddleware::allowOnly(['US', 'CA']));

// Block specific countries
$router->middleware(GeoBlockMiddleware::blockOnly(['XX', 'YY']));
```

## 8. Request Size Limiting

```php
use Lalaz\Waf\Middlewares\RequestSizeLimiterMiddleware;

// API limits (1MB)
$router->middleware(RequestSizeLimiterMiddleware::forApi());

// Upload limits (10MB)
$router->middleware(RequestSizeLimiterMiddleware::forUploads());

// Strict limits (100KB)
$router->middleware(RequestSizeLimiterMiddleware::strict());
```

## 9. HTTP Method Filtering

```php
use Lalaz\Waf\Middlewares\HttpMethodMiddleware;

// Read-only (GET, HEAD, OPTIONS)
$router->middleware(HttpMethodMiddleware::readOnly());

// RESTful (GET, POST, PUT, PATCH, DELETE, OPTIONS)
$router->middleware(HttpMethodMiddleware::restful());
```

## 10. Complete Example

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Middlewares\HelmetMiddleware;
use Lalaz\Waf\Middlewares\CorsMiddleware;
use Lalaz\Waf\Middlewares\RequestSizeLimiterMiddleware;

// Public API routes
$router->group(['prefix' => '/api', 'middleware' => [
    RateLimitMiddleware::perMinute(60),
    SanitizationMiddleware::strict(),
    HelmetMiddleware::api(),
    CorsMiddleware::allowAll(),
    RequestSizeLimiterMiddleware::forApi(),
]], function ($router) {
    $router->get('/users', [UserController::class, 'index']);
    $router->post('/users', [UserController::class, 'store']);
});

// Admin routes (stricter)
$router->group(['prefix' => '/admin', 'middleware' => [
    RateLimitMiddleware::perMinute(30),
    SanitizationMiddleware::strict(),
    HelmetMiddleware::strict(),
    IpFilterMiddleware::whitelist(['10.0.0.0/8']),
]], function ($router) {
    $router->get('/dashboard', [AdminController::class, 'dashboard']);
});
```

## Next Steps

- [Concepts](concepts.md) — Understand the architecture
- [Rate Limiting](rate-limit/index.md) — Deep dive into rate limiting
- [Threat Detection](detection/index.md) — Learn about threat detection
- [Middlewares](middlewares/index.md) — All available middlewares
