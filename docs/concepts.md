# Concepts

Core concepts and architecture of the WAF package.

---

## Overview

The WAF (Web Application Firewall) package provides multiple layers of protection for web applications. Each component is designed to be used independently or combined for defense-in-depth.

## Defense Layers

```
Request Flow
│
▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 1: Trusted Proxy                                          │
│  • Resolve real client IP behind proxies/load balancers          │
└──────────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 2: IP Filtering                                           │
│  • Block/allow by IP address, CIDR, range, or wildcard           │
└──────────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 3: Geo Blocking                                           │
│  • Block/allow by country or continent                           │
└──────────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 4: Rate Limiting                                          │
│  • Throttle requests using token bucket algorithm                │
└──────────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 5: HTTP Method Filtering                                  │
│  • Allow only specific HTTP methods                              │
└──────────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 6: Request Size Limiting                                  │
│  • Block oversized requests                                      │
└──────────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 7: Threat Detection                                       │
│  • Scan for XSS, SQLi, Path Traversal, Command Injection         │
└──────────────────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│  Layer 8: Security Headers                                       │
│  • Add CSP, HSTS, X-Frame-Options, etc.                          │
└──────────────────────────────────────────────────────────────────┘
│
▼
Application
```

## Rate Limiting

### Token Bucket Algorithm

The rate limiter uses the token bucket algorithm:

```
Bucket Capacity: 10 tokens
Refill Rate: 1 token/second

Time 0:  [■■■■■■■■■■] 10/10 tokens → Request allowed, 9 tokens left
Time 1:  [■■■■■■■■■□] 9/10 tokens  → Token refilled
Time 1:  [■■■■■■■■□□] 8/10 tokens  → Request allowed, 8 tokens left
...
Time 10: [□□□□□□□□□□] 0/10 tokens  → Request blocked (rate limited)
```

### Storage Backends

| Backend | Use Case | Persistence | Distribution |
|---------|----------|-------------|--------------|
| Memory | Testing | No | Single process |
| APCu | Single server | Yes (restart) | Single server |
| Redis | Production | Yes | Distributed |
| Cache | Integration | Depends | Depends |

## Threat Detection

### Detection Types

| Type | Description | Example |
|------|-------------|---------|
| XSS | Cross-Site Scripting | `<script>alert('xss')</script>` |
| SQL Injection | Database attacks | `' OR 1=1 --` |
| Path Traversal | File access attacks | `../../../etc/passwd` |
| Command Injection | Shell command attacks | `; rm -rf /` |

### Pattern Matching

Each threat type has a dedicated pattern set:

```php
// XSS patterns detect JavaScript injection
XssPatterns::getPatterns()
// [
//     '/<script\b[^>]*>(.*?)<\/script>/is',
//     '/javascript\s*:/i',
//     '/on\w+\s*=\s*["\']?[^"\']*["\']?/i',
//     ...
// ]
```

### Severity Levels

```php
ThreatType::XSS->severity();              // 8
ThreatType::SQL_INJECTION->severity();    // 9
ThreatType::PATH_TRAVERSAL->severity();   // 7
ThreatType::COMMAND_INJECTION->severity(); // 10
```

## IP Filtering

### Matching Strategies

| Strategy | Example | Description |
|----------|---------|-------------|
| Exact | `192.168.1.100` | Exact IP match |
| CIDR | `192.168.1.0/24` | Network range |
| Wildcard | `192.168.1.*` | Wildcard pattern |
| Range | `192.168.1.1-192.168.1.100` | IP range |

### Special IP Detection

```php
IpMatcher::isPrivate('192.168.1.1');   // true
IpMatcher::isPrivate('8.8.8.8');       // false
IpMatcher::isLoopback('127.0.0.1');    // true
IpMatcher::isLoopback('::1');          // true
```

## Geo Blocking

### GeoLocation Object

The `GeoLocation` value object contains:

| Property | Description |
|----------|-------------|
| `country` | ISO 3166-1 alpha-2 code (US, CA, BR) |
| `countryName` | Full country name |
| `region` | State/province |
| `city` | City name |
| `latitude` | Geographic latitude |
| `longitude` | Geographic longitude |
| `isp` | Internet Service Provider |
| `isProxy` | VPN/Proxy detection |
| `isVpn` | VPN detection |
| `isTor` | Tor exit node detection |

### Geo Providers

| Provider | Data Source | Accuracy |
|----------|-------------|----------|
| ArrayGeoProvider | Static array | Testing only |
| MaxMindGeoProvider | MaxMind GeoIP2 | Production |
| IpInfoGeoProvider | ipinfo.io API | Production |

## Security Headers

### Helmet Headers

| Header | Purpose |
|--------|---------|
| Content-Security-Policy | Controls resource loading |
| X-Frame-Options | Prevents clickjacking |
| X-Content-Type-Options | Prevents MIME sniffing |
| X-XSS-Protection | Browser XSS filter |
| Strict-Transport-Security | Forces HTTPS |
| Referrer-Policy | Controls referrer info |
| Permissions-Policy | Controls browser features |

## CORS

### Cross-Origin Resource Sharing

```
Browser                           Server
   │                                 │
   │  OPTIONS /api/data              │
   │  Origin: https://app.com        │
   │ ──────────────────────────────► │
   │                                 │
   │  Access-Control-Allow-Origin    │
   │  Access-Control-Allow-Methods   │
   │ ◄────────────────────────────── │
   │                                 │
   │  GET /api/data                  │
   │  Origin: https://app.com        │
   │ ──────────────────────────────► │
   │                                 │
   │  { data: ... }                  │
   │ ◄────────────────────────────── │
```

## Middleware Composition

Middlewares can be composed for layered security:

```php
// Recommended order (outside to inside)
$middleware = [
    TrustedProxyMiddleware::forCloudflare(),  // 1. Resolve real IP
    IpFilterMiddleware::blacklist([...]),      // 2. Filter IPs
    GeoBlockMiddleware::allowOnly(['US']),     // 3. Geo block
    RateLimitMiddleware::perMinute(60),        // 4. Rate limit
    HttpMethodMiddleware::restful(),           // 5. Method filter
    RequestSizeLimiterMiddleware::forApi(),    // 6. Size limit
    SanitizationMiddleware::strict(),          // 7. Threat scan
    HelmetMiddleware::strict(),                // 8. Security headers
    CorsMiddleware::strict($origin),           // 9. CORS
];
```

## Next Steps

- [Rate Limiting](rate-limit/index.md) — Deep dive into rate limiting
- [Threat Detection](detection/index.md) — Learn about threat detection
- [Middlewares](middlewares/index.md) — All available middlewares
