# API Reference

Complete API documentation for the WAF package.

---

## Detection Module

### ThreatDetector

```php
namespace Lalaz\Waf\Detection;

class ThreatDetector
{
    // Factory methods
    public static function all(): self;
    public static function xssOnly(): self;
    public static function sqlInjectionOnly(): self;
    public static function pathTraversalOnly(): self;
    public static function fromConfig(array $config): self;
    
    // Instance methods
    public function scan(string $input): array;
    public function scanArray(array $data): array;
    public function isClean(string $input): bool;
}
```

### Threat

```php
namespace Lalaz\Waf\Detection;

final class Threat
{
    public function __construct(
        ThreatType $type,
        string $pattern,
        string $matchedValue
    );
    
    public function type(): ThreatType;
    public function pattern(): string;
    public function matchedValue(): string;
}
```

### ThreatType

```php
namespace Lalaz\Waf\Detection;

enum ThreatType: string
{
    case XSS = 'xss';
    case SQL_INJECTION = 'sql_injection';
    case PATH_TRAVERSAL = 'path_traversal';
    case COMMAND_INJECTION = 'command_injection';
    
    public function label(): string;
    public function severity(): int;
}
```

### PatternSet

```php
namespace Lalaz\Waf\Detection\Patterns;

abstract class PatternSet
{
    public static function getPatterns(): array;
    public static function getThreatType(): ThreatType;
}
```

---

## RateLimit Module

### RateLimiter

```php
namespace Lalaz\Waf\RateLimit;

class RateLimiter
{
    public function __construct(?RateLimitStoreInterface $store = null);
    
    public function tooManyAttempts(string $key, int $maxAttempts, int $decaySeconds = 60): bool;
    public function hit(string $key, int $decaySeconds = 60): int;
    public function remaining(string $key, int $maxAttempts, int $decaySeconds = 60): int;
    public function availableIn(string $key): int;
    public function resetAt(string $key): ?int;
    public function clear(string $key): void;
}
```

### RateLimitStoreInterface

```php
namespace Lalaz\Waf\RateLimit\Contracts;

interface RateLimitStoreInterface
{
    public function get(string $key): ?array;
    public function set(string $key, int $attempts, int $decaySeconds): void;
    public function increment(string $key, int $decaySeconds): int;
    public function clear(string $key): void;
}
```

### RateLimitExceededException

```php
namespace Lalaz\Waf\RateLimit;

class RateLimitExceededException extends \RuntimeException
{
    public function __construct(int $retryAfter);
    public function getRetryAfter(): int;
}
```

### MemoryStore

```php
namespace Lalaz\Waf\RateLimit\Stores;

class MemoryStore implements RateLimitStoreInterface
{
    public function __construct();
    public function get(string $key): ?array;
    public function set(string $key, int $attempts, int $decaySeconds): void;
    public function increment(string $key, int $decaySeconds): int;
    public function clear(string $key): void;
}
```

### RedisStore

```php
namespace Lalaz\Waf\RateLimit\Stores;

class RedisStore implements RateLimitStoreInterface
{
    public function __construct($redis, string $prefix = 'rate_limit:');
    public function get(string $key): ?array;
    public function set(string $key, int $attempts, int $decaySeconds): void;
    public function increment(string $key, int $decaySeconds): int;
    public function clear(string $key): void;
}
```

### APCuStore

```php
namespace Lalaz\Waf\RateLimit\Stores;

class APCuStore implements RateLimitStoreInterface
{
    public function __construct(string $prefix = 'rate_limit:');
    public function get(string $key): ?array;
    public function set(string $key, int $attempts, int $decaySeconds): void;
    public function increment(string $key, int $decaySeconds): int;
    public function clear(string $key): void;
}
```

### CacheStore

```php
namespace Lalaz\Waf\RateLimit\Stores;

class CacheStore implements RateLimitStoreInterface
{
    public function __construct($cache, string $prefix = 'rate_limit:');
    public function get(string $key): ?array;
    public function set(string $key, int $attempts, int $decaySeconds): void;
    public function increment(string $key, int $decaySeconds): int;
    public function clear(string $key): void;
}
```

---

## IpFilter Module

### IpMatcher

```php
namespace Lalaz\Waf\IpFilter;

class IpMatcher
{
    public static function matches(string $ip, string $pattern): bool;
    public static function matchesCidr(string $ip, string $cidr): bool;
    public static function matchesWildcard(string $ip, string $pattern): bool;
    public static function matchesRange(string $ip, string $range): bool;
    public static function isPrivate(string $ip): bool;
    public static function isLoopback(string $ip): bool;
}
```

### IpList

```php
namespace Lalaz\Waf\IpFilter;

class IpList
{
    public function __construct(
        array $ips = [],
        ?callable $onAdd = null,
        ?callable $onRemove = null
    );
    
    public function add(string $ip): void;
    public function remove(string $ip): void;
    public function contains(string $ip): bool;
    public function all(): array;
    public function clear(): void;
    public function count(): int;
    public function importFromFile(string $path): void;
    public function exportToFile(string $path): void;
}
```

---

## Geo Module

### GeoLocation

```php
namespace Lalaz\Waf\Geo;

final class GeoLocation
{
    public static function create(array $data): self;
    public static function unknown(): self;
    
    public function country(): ?string;
    public function countryName(): ?string;
    public function region(): ?string;
    public function city(): ?string;
    public function latitude(): ?float;
    public function longitude(): ?float;
    public function isp(): ?string;
    public function isProxy(): bool;
    public function isVpn(): bool;
    public function isTor(): bool;
    public function isKnown(): bool;
    public function continent(): ?string;
    public function toArray(): array;
}
```

### GeoProviderInterface

```php
namespace Lalaz\Waf\Geo\Contracts;

interface GeoProviderInterface
{
    public function lookup(string $ip): GeoLocation;
}
```

### ArrayGeoProvider

```php
namespace Lalaz\Waf\Geo\Providers;

class ArrayGeoProvider implements GeoProviderInterface
{
    public function __construct(array $data = []);
    public function lookup(string $ip): GeoLocation;
    public function add(string $ip, GeoLocation $location): void;
}
```

---

## Middlewares

### CorsMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class CorsMiddleware implements MiddlewareInterface
{
    public static function allowAll(): self;
    public static function strict(string $origin): self;
    
    public function __construct(
        array $allowedOrigins = ['*'],
        array $allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        array $allowedHeaders = ['Content-Type', 'Authorization'],
        array $exposedHeaders = [],
        int $maxAge = 86400,
        bool $allowCredentials = false
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```

### GeoBlockMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class GeoBlockMiddleware implements MiddlewareInterface
{
    public static function allowOnly(array $countries): self;
    public static function blockOnly(array $countries): self;
    public static function strict(array $countries): self;
    
    public function __construct(
        GeoProviderInterface $provider,
        array $allowedCountries = [],
        array $blockedCountries = [],
        bool $blockVpn = false,
        bool $blockProxy = false,
        bool $blockTor = false,
        ?callable $onBlock = null
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```

### HelmetMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class HelmetMiddleware implements MiddlewareInterface
{
    public static function strict(): self;
    public static function development(): self;
    public static function api(): self;
    
    public function __construct(
        ?string $contentSecurityPolicy = null,
        string $xFrameOptions = 'DENY',
        string $xContentTypeOptions = 'nosniff',
        string $xXssProtection = '1; mode=block',
        ?string $strictTransportSecurity = null,
        string $referrerPolicy = 'strict-origin-when-cross-origin',
        ?string $permissionsPolicy = null
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```

### HttpMethodMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class HttpMethodMiddleware implements MiddlewareInterface
{
    public static function readOnly(): self;
    public static function restful(): self;
    public static function safe(): self;
    
    public function __construct(
        array $allowedMethods,
        ?callable $onBlock = null
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```

### IpFilterMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class IpFilterMiddleware implements MiddlewareInterface
{
    public static function whitelist(array $ips): self;
    public static function blacklist(array $ips): self;
    public static function internalOnly(): self;
    
    public function __construct(
        ?IpList $whitelist = null,
        ?IpList $blacklist = null,
        string $mode = 'whitelist',
        ?callable $onBlock = null
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```

### RateLimitMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class RateLimitMiddleware implements MiddlewareInterface
{
    public static function perMinute(int $max, int $minutes = 1): self;
    public static function perHour(int $max, int $hours = 1): self;
    public static function perDay(int $max): self;
    public static function forLogin(): self;
    public static function forApi(): self;
    
    public function __construct(
        ?RateLimiter $limiter = null,
        int $maxAttempts = 60,
        int $decaySeconds = 60,
        ?callable $keyResolver = null
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```

### RequestSizeLimiterMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class RequestSizeLimiterMiddleware implements MiddlewareInterface
{
    public static function forApi(): self;
    public static function forUploads(): self;
    public static function strict(): self;
    
    public function __construct(
        int $maxBodySize = 1048576,
        int $maxHeaderSize = 8192,
        ?callable $onBlock = null
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```

### SanitizationMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class SanitizationMiddleware implements MiddlewareInterface
{
    public static function strict(): self;
    public static function logOnly(): self;
    public static function basic(): self;
    public static function forApi(): self;
    
    public function __construct(
        ?ThreatDetector $detector = null,
        string $mode = 'block',
        ?LoggerInterface $logger = null,
        array $excludedPaths = [],
        array $excludedParams = []
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```

### TrustedProxyMiddleware

```php
namespace Lalaz\Waf\Middlewares;

class TrustedProxyMiddleware implements MiddlewareInterface
{
    public static function forCloudflare(): self;
    public static function forNginx(): self;
    public static function forAwsAlb(): self;
    
    public function __construct(
        array $trustedProxies = [],
        array $trustedHeaders = ['X-Forwarded-For', 'X-Forwarded-Proto', 'X-Forwarded-Host']
    );
    
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface;
}
```
