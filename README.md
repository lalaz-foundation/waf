# WAF Package

Web Application Firewall for Lalaz Framework.

## Installation

```bash
composer require lalaz/waf
```

## Quick Start

```php
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Middlewares\CorsMiddleware;

// Rate limiting
$router->middleware(RateLimitMiddleware::perMinute(60));

// Threat detection
$router->middleware(SanitizationMiddleware::strict());

// CORS
$router->middleware(CorsMiddleware::allowAll());
```

## Features

- **Rate Limiting** — Token bucket algorithm with multiple backends
- **Threat Detection** — XSS, SQL Injection, Path Traversal, Command Injection
- **IP Filtering** — Whitelist/blacklist with CIDR support
- **Geo Blocking** — Block/allow by country or continent
- **CORS** — Cross-origin resource sharing
- **Security Headers** — Helmet middleware
- **Request Size Limiting** — Protect against oversized payloads

## Documentation

See [docs/](docs/) for complete documentation.
