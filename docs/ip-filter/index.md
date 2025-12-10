# IP Filtering

Filter requests by IP address using whitelist/blacklist.

---

## Overview

The IP filtering module provides powerful IP matching capabilities including exact match, CIDR notation, wildcards, and ranges.

## Quick Start

```php
use Lalaz\Waf\IpFilter\IpList;
use Lalaz\Waf\IpFilter\IpMatcher;

// Check if IP is in a CIDR range
$matches = IpMatcher::matches('192.168.1.100', '192.168.1.0/24'); // true

// Create an IP list
$blacklist = new IpList();
$blacklist->add('10.0.0.1');
$blacklist->add('192.168.0.0/16');

if ($blacklist->contains('192.168.1.100')) {
    // IP is blacklisted
}
```

## IpMatcher

Static utility class for IP matching operations.

### Methods

#### `matches(string $ip, string $pattern): bool`

Check if an IP matches a pattern. Supports CIDR, wildcard, and range patterns.

```php
// Exact match
IpMatcher::matches('192.168.1.1', '192.168.1.1'); // true

// CIDR match
IpMatcher::matches('192.168.1.100', '192.168.1.0/24'); // true

// Wildcard match
IpMatcher::matches('192.168.1.100', '192.168.1.*'); // true

// Range match
IpMatcher::matches('192.168.1.50', '192.168.1.1-192.168.1.100'); // true
```

#### `matchesCidr(string $ip, string $cidr): bool`

Check if an IP is within a CIDR range.

```php
IpMatcher::matchesCidr('192.168.1.100', '192.168.1.0/24'); // true
IpMatcher::matchesCidr('10.0.0.1', '192.168.1.0/24');      // false
```

#### `matchesWildcard(string $ip, string $pattern): bool`

Check if an IP matches a wildcard pattern.

```php
IpMatcher::matchesWildcard('192.168.1.100', '192.168.1.*');   // true
IpMatcher::matchesWildcard('192.168.1.100', '192.168.*.*');   // true
IpMatcher::matchesWildcard('192.168.1.100', '*.168.1.100');   // true
```

#### `matchesRange(string $ip, string $range): bool`

Check if an IP is within a range.

```php
IpMatcher::matchesRange('192.168.1.50', '192.168.1.1-192.168.1.100'); // true
IpMatcher::matchesRange('192.168.1.150', '192.168.1.1-192.168.1.100'); // false
```

#### `isPrivate(string $ip): bool`

Check if an IP is in a private range.

```php
IpMatcher::isPrivate('192.168.1.1'); // true (192.168.0.0/16)
IpMatcher::isPrivate('10.0.0.1');    // true (10.0.0.0/8)
IpMatcher::isPrivate('172.16.0.1');  // true (172.16.0.0/12)
IpMatcher::isPrivate('8.8.8.8');     // false
```

#### `isLoopback(string $ip): bool`

Check if an IP is a loopback address.

```php
IpMatcher::isLoopback('127.0.0.1'); // true
IpMatcher::isLoopback('::1');       // true
IpMatcher::isLoopback('127.0.0.5'); // true
IpMatcher::isLoopback('8.8.8.8');   // false
```

## IpList

Manages a list of IP addresses with persistence support.

### Constructor

```php
use Lalaz\Waf\IpFilter\IpList;

// Empty list
$list = new IpList();

// With initial IPs
$list = new IpList([
    '192.168.1.1',
    '10.0.0.0/8',
    '172.16.*.*',
]);

// With persistence callback
$list = new IpList(
    ips: [],
    onAdd: fn(string $ip) => $db->insert('blacklist', ['ip' => $ip]),
    onRemove: fn(string $ip) => $db->delete('blacklist', ['ip' => $ip]),
);
```

### Methods

#### `add(string $ip): void`

Add an IP to the list.

```php
$list->add('192.168.1.1');
$list->add('10.0.0.0/8');
$list->add('172.16.*.*');
```

#### `remove(string $ip): void`

Remove an IP from the list.

```php
$list->remove('192.168.1.1');
```

#### `contains(string $ip): bool`

Check if an IP matches any entry in the list.

```php
$list->add('192.168.1.0/24');
$list->contains('192.168.1.100'); // true
$list->contains('192.168.2.1');   // false
```

#### `all(): array`

Get all entries in the list.

```php
$entries = $list->all();
```

#### `clear(): void`

Remove all entries from the list.

```php
$list->clear();
```

#### `count(): int`

Get the number of entries in the list.

```php
$count = $list->count();
```

### File Import/Export

```php
// Import from file (one IP per line)
$list->importFromFile('/path/to/blacklist.txt');

// Export to file
$list->exportToFile('/path/to/blacklist.txt');
```

## IpFilterMiddleware

Use the middleware for automatic IP filtering:

```php
use Lalaz\Waf\Middlewares\IpFilterMiddleware;

// Whitelist mode (only allow listed IPs)
$middleware = IpFilterMiddleware::whitelist([
    '192.168.1.0/24',
    '10.0.0.0/8',
]);

// Blacklist mode (block listed IPs)
$middleware = IpFilterMiddleware::blacklist([
    '203.0.113.0/24', // Known bad actors
]);

// Internal only (private IPs only)
$middleware = IpFilterMiddleware::internalOnly();
```

### Custom Configuration

```php
$whitelist = new IpList(['192.168.1.0/24']);
$blacklist = new IpList(['10.0.0.1']);

$middleware = new IpFilterMiddleware(
    whitelist: $whitelist,
    blacklist: $blacklist,
    mode: 'whitelist', // 'whitelist', 'blacklist', 'both'
    onBlock: fn($ip, $request) => Log::warning("Blocked IP: {$ip}"),
);
```

## Example: Admin Protection

```php
use Lalaz\Waf\IpFilter\IpList;
use Lalaz\Waf\Middlewares\IpFilterMiddleware;

// Load admin IPs from database
$adminIps = $db->query('SELECT ip FROM admin_whitelist');

$middleware = IpFilterMiddleware::whitelist($adminIps);

$router->group(['prefix' => '/admin', 'middleware' => [$middleware]], function ($router) {
    $router->get('/dashboard', [AdminController::class, 'dashboard']);
});
```

## Example: Dynamic Blacklist

```php
use Lalaz\Waf\IpFilter\IpList;

class SecurityService
{
    private IpList $blacklist;
    
    public function __construct()
    {
        $this->blacklist = new IpList(
            ips: $this->loadFromDatabase(),
            onAdd: fn($ip) => $this->persistToDatabase($ip),
            onRemove: fn($ip) => $this->removeFromDatabase($ip),
        );
    }
    
    public function blockIp(string $ip, string $reason): void
    {
        $this->blacklist->add($ip);
        
        Log::warning("IP blocked: {$ip}", ['reason' => $reason]);
    }
    
    public function isBlocked(string $ip): bool
    {
        return $this->blacklist->contains($ip);
    }
    
    private function loadFromDatabase(): array
    {
        return DB::table('ip_blacklist')->pluck('ip')->toArray();
    }
    
    private function persistToDatabase(string $ip): void
    {
        DB::table('ip_blacklist')->insert([
            'ip' => $ip,
            'created_at' => now(),
        ]);
    }
    
    private function removeFromDatabase(string $ip): void
    {
        DB::table('ip_blacklist')->where('ip', $ip)->delete();
    }
}
```

## Best Practices

1. **Use CIDR notation** for network ranges instead of individual IPs
2. **Combine whitelist and blacklist** for defense in depth
3. **Log blocked requests** for security monitoring
4. **Persist IP lists** to database or file for persistence
5. **Consider rate limiting** before IP blocking for less severe cases

## Next Steps

- [Geo Blocking](../geo/index.md) — Block by geographic location
- [Rate Limiting](../rate-limit/index.md) — Request rate limiting
- [Middlewares](../middlewares/index.md) — All available middlewares
