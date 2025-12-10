# Middlewares

All available middleware components for WAF.

---

## Overview

The WAF package provides a comprehensive set of PSR-15 compatible middlewares for web application security.

## Middleware List

| Middleware | Purpose |
|------------|---------|
| [CorsMiddleware](#corsmiddleware) | Cross-Origin Resource Sharing |
| [GeoBlockMiddleware](#geoblockmiddleware) | Geographic blocking |
| [HelmetMiddleware](#helmetmiddleware) | Security headers |
| [HttpMethodMiddleware](#httpmethodmiddleware) | HTTP method filtering |
| [IpFilterMiddleware](#ipfiltermiddleware) | IP whitelist/blacklist |
| [RateLimitMiddleware](#ratelimitmiddleware) | Request rate limiting |
| [RequestSizeLimiterMiddleware](#requestsizelimitermiddleware) | Request size limits |
| [SanitizationMiddleware](#sanitizationmiddleware) | Threat detection |
| [TrustedProxyMiddleware](#trustedproxymiddleware) | Proxy IP resolution |

---

## CorsMiddleware

Handle Cross-Origin Resource Sharing (CORS) requests.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\CorsMiddleware;

// Allow all origins (development)
$middleware = CorsMiddleware::allowAll();

// Strict mode with specific origin
$middleware = CorsMiddleware::strict('https://example.com');
```

### Custom Configuration

```php
$middleware = new CorsMiddleware(
    allowedOrigins: ['https://app.example.com', 'https://admin.example.com'],
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['X-Request-Id'],
    maxAge: 86400,
    allowCredentials: true,
);
```

### Response Headers

- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Expose-Headers`
- `Access-Control-Max-Age`
- `Access-Control-Allow-Credentials`

---

## GeoBlockMiddleware

Block or allow requests based on geographic location.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;

// Allow only specific countries
$middleware = GeoBlockMiddleware::allowOnly(['US', 'CA', 'GB']);

// Block specific countries
$middleware = GeoBlockMiddleware::blockOnly(['CN', 'RU']);

// Strict mode (also block VPN/Proxy/Tor)
$middleware = GeoBlockMiddleware::strict(['US', 'CA']);
```

### Custom Configuration

```php
$middleware = new GeoBlockMiddleware(
    provider: $geoProvider,
    allowedCountries: ['US', 'CA'],
    blockedCountries: [],
    blockVpn: true,
    blockProxy: true,
    blockTor: true,
    onBlock: fn($ip, $location) => Log::warning("Blocked: {$ip}"),
);
```

---

## HelmetMiddleware

Add security headers to responses.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\HelmetMiddleware;

// Production-ready strict headers
$middleware = HelmetMiddleware::strict();

// Development mode (relaxed CSP)
$middleware = HelmetMiddleware::development();

// API mode (no CSP, CORS-friendly)
$middleware = HelmetMiddleware::api();
```

### Custom Configuration

```php
$middleware = new HelmetMiddleware(
    contentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'",
    xFrameOptions: 'DENY',
    xContentTypeOptions: 'nosniff',
    xXssProtection: '1; mode=block',
    strictTransportSecurity: 'max-age=31536000; includeSubDomains',
    referrerPolicy: 'strict-origin-when-cross-origin',
    permissionsPolicy: 'camera=(), microphone=(), geolocation=()',
);
```

### Headers Added

| Header | Purpose |
|--------|---------|
| Content-Security-Policy | Controls resource loading |
| X-Frame-Options | Prevents clickjacking |
| X-Content-Type-Options | Prevents MIME sniffing |
| X-XSS-Protection | Browser XSS filter |
| Strict-Transport-Security | Forces HTTPS |
| Referrer-Policy | Controls referrer info |
| Permissions-Policy | Controls browser features |

---

## HttpMethodMiddleware

Filter requests by HTTP method.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\HttpMethodMiddleware;

// Read-only (GET, HEAD, OPTIONS)
$middleware = HttpMethodMiddleware::readOnly();

// RESTful (GET, POST, PUT, PATCH, DELETE, OPTIONS)
$middleware = HttpMethodMiddleware::restful();

// Safe methods only (GET, HEAD, OPTIONS, TRACE)
$middleware = HttpMethodMiddleware::safe();
```

### Custom Configuration

```php
$middleware = new HttpMethodMiddleware(
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    onBlock: fn($method, $request) => Log::warning("Blocked method: {$method}"),
);
```

---

## IpFilterMiddleware

Filter requests by IP address.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\IpFilterMiddleware;

// Whitelist mode (only allow listed IPs)
$middleware = IpFilterMiddleware::whitelist([
    '192.168.1.0/24',
    '10.0.0.0/8',
]);

// Blacklist mode (block listed IPs)
$middleware = IpFilterMiddleware::blacklist([
    '203.0.113.0/24',
]);

// Internal only (private IPs only)
$middleware = IpFilterMiddleware::internalOnly();
```

### Custom Configuration

```php
$middleware = new IpFilterMiddleware(
    whitelist: new IpList(['192.168.1.0/24']),
    blacklist: new IpList(['10.0.0.1']),
    mode: 'both', // 'whitelist', 'blacklist', 'both'
    onBlock: fn($ip, $request) => Log::warning("Blocked IP: {$ip}"),
);
```

---

## RateLimitMiddleware

Limit the number of requests per time window.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;

// 60 requests per minute
$middleware = RateLimitMiddleware::perMinute(60);

// 1000 requests per hour
$middleware = RateLimitMiddleware::perHour(1000);

// 10000 requests per day
$middleware = RateLimitMiddleware::perDay(10000);

// Login protection (5 per minute)
$middleware = RateLimitMiddleware::forLogin();

// API rate limiting (100 per minute)
$middleware = RateLimitMiddleware::forApi();
```

### Custom Configuration

```php
$middleware = new RateLimitMiddleware(
    limiter: new RateLimiter(new RedisStore($redis)),
    maxAttempts: 100,
    decaySeconds: 300,
    keyResolver: fn($request) => 'api:' . $request->getAttribute('user_id'),
);
```

### Response Headers

- `X-RateLimit-Limit` — Maximum requests allowed
- `X-RateLimit-Remaining` — Remaining requests
- `X-RateLimit-Reset` — Unix timestamp when limit resets
- `Retry-After` — Seconds until retry (when limited)

---

## RequestSizeLimiterMiddleware

Limit the size of incoming requests.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\RequestSizeLimiterMiddleware;

// API limits (1MB)
$middleware = RequestSizeLimiterMiddleware::forApi();

// Upload limits (10MB)
$middleware = RequestSizeLimiterMiddleware::forUploads();

// Strict limits (100KB)
$middleware = RequestSizeLimiterMiddleware::strict();
```

### Custom Configuration

```php
$middleware = new RequestSizeLimiterMiddleware(
    maxBodySize: 5 * 1024 * 1024, // 5MB
    maxHeaderSize: 8 * 1024,       // 8KB
    onBlock: fn($size, $request) => Log::warning("Request too large: {$size} bytes"),
);
```

---

## SanitizationMiddleware

Detect and handle malicious input.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\SanitizationMiddleware;

// Block all threats (recommended)
$middleware = SanitizationMiddleware::strict();

// Log threats but don't block
$middleware = SanitizationMiddleware::logOnly();

// Basic sanitization (HTML entities)
$middleware = SanitizationMiddleware::basic();

// API mode (JSON-aware)
$middleware = SanitizationMiddleware::forApi();
```

### Custom Configuration

```php
$middleware = new SanitizationMiddleware(
    detector: ThreatDetector::all(),
    mode: 'block', // 'block', 'log', 'sanitize'
    logger: $logger,
    excludedPaths: ['/webhooks/*'],
    excludedParams: ['signature', 'token'],
);
```

---

## TrustedProxyMiddleware

Resolve the real client IP when behind proxies.

### Factory Methods

```php
use Lalaz\Waf\Middlewares\TrustedProxyMiddleware;

// Cloudflare proxy
$middleware = TrustedProxyMiddleware::forCloudflare();

// Nginx reverse proxy
$middleware = TrustedProxyMiddleware::forNginx();

// AWS Application Load Balancer
$middleware = TrustedProxyMiddleware::forAwsAlb();
```

### Custom Configuration

```php
$middleware = new TrustedProxyMiddleware(
    trustedProxies: ['10.0.0.0/8', '172.16.0.0/12'],
    trustedHeaders: [
        'X-Forwarded-For',
        'X-Forwarded-Proto',
        'X-Forwarded-Host',
    ],
);
```

---

## Middleware Order

Recommended order for middleware stack:

```php
$middlewares = [
    // 1. Resolve real IP first
    TrustedProxyMiddleware::forCloudflare(),
    
    // 2. Filter by IP
    IpFilterMiddleware::blacklist([...]),
    
    // 3. Filter by location
    GeoBlockMiddleware::allowOnly(['US']),
    
    // 4. Rate limit
    RateLimitMiddleware::perMinute(60),
    
    // 5. Filter HTTP methods
    HttpMethodMiddleware::restful(),
    
    // 6. Limit request size
    RequestSizeLimiterMiddleware::forApi(),
    
    // 7. Detect threats
    SanitizationMiddleware::strict(),
    
    // 8. Add security headers
    HelmetMiddleware::strict(),
    
    // 9. Handle CORS
    CorsMiddleware::strict($origin),
];
```

## Next Steps

- [Rate Limiting](../rate-limit/index.md) — Deep dive into rate limiting
- [Threat Detection](../detection/index.md) — Learn about threat detection
- [Examples](../examples/index.md) — Practical examples
