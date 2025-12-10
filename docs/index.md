# WAF Package Documentation

Web Application Firewall for Lalaz Framework.

## Documentation Index

| Document | Purpose |
|----------|---------|
| [Quick Start](quick-start.md) | Get started in 5 minutes |
| [Installation](installation.md) | Installation and configuration |
| [Concepts](concepts.md) | Core concepts and architecture |
| [Glossary](glossary.md) | Terminology and definitions |

### Module Documentation

| Module | Purpose |
|--------|---------|
| [Rate Limiting](rate-limit/index.md) | Request rate limiting |
| [Threat Detection](detection/index.md) | XSS, SQL Injection, etc. |
| [IP Filter](ip-filter/index.md) | IP whitelist/blacklist |
| [Geo Blocking](geo/index.md) | Geographic blocking |
| [Middlewares](middlewares/index.md) | All middleware components |

### Reference

| Document | Purpose |
|----------|---------|
| [API Reference](api-reference.md) | Complete API documentation |
| [Examples](examples/index.md) | Practical examples |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         WAF Package                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Detection  │  │  Rate Limit  │  │  IP Filter   │           │
│  │              │  │              │  │              │           │
│  │ XSS          │  │ TokenBucket  │  │ IpList       │           │
│  │ SQLi         │  │ Stores:      │  │ IpMatcher    │           │
│  │ PathTraversal│  │ • Memory     │  │ • CIDR       │           │
│  │ CommandInj   │  │ • Redis      │  │ • Wildcard   │           │
│  │              │  │ • APCu       │  │ • Range      │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│                                                                  │
│  ┌──────────────┐  ┌────────────────────────────────────────┐   │
│  │     Geo      │  │             Middlewares                 │   │
│  │              │  │                                         │   │
│  │ GeoLocation  │  │  CorsMiddleware      HelmetMiddleware   │   │
│  │ GeoProvider  │  │  RateLimitMiddleware IpFilterMiddleware │   │
│  │ • Array      │  │  GeoBlockMiddleware  SanitizationMW     │   │
│  │ • MaxMind    │  │  HttpMethodMiddleware RequestSizeMW     │   │
│  │              │  │  TrustedProxyMiddleware                 │   │
│  └──────────────┘  └────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Example

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Middlewares\HelmetMiddleware;
use Lalaz\Waf\Middlewares\CorsMiddleware;

// Protect your routes with layered security
$router->group(['middleware' => [
    RateLimitMiddleware::perMinute(60),
    SanitizationMiddleware::strict(),
    HelmetMiddleware::strict(),
    CorsMiddleware::strict('https://example.com'),
]], function ($router) {
    $router->get('/api/data', [DataController::class, 'index']);
});
```

## Key Features

### Rate Limiting
- Token bucket algorithm
- Multiple storage backends (Memory, Redis, APCu, Cache)
- Per-route or global limiting
- Automatic retry-after headers

### Threat Detection
- XSS (Cross-Site Scripting) detection
- SQL Injection detection
- Path Traversal detection
- Command Injection detection
- Configurable patterns

### IP Filtering
- Whitelist/blacklist support
- CIDR notation
- Wildcard matching
- Range matching
- Private/loopback detection

### Geo Blocking
- Block/allow by country
- Block/allow by continent
- Pluggable geo providers
- VPN/Proxy/Tor detection

### Security Headers
- Content Security Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- And more...

## Requirements

- PHP 8.2+
- PSR-7 HTTP Message implementation
- PSR-15 HTTP Middleware implementation

## Next Steps

1. [Installation](installation.md) — Install the package
2. [Quick Start](quick-start.md) — Get started in 5 minutes
3. [Concepts](concepts.md) — Understand the architecture
