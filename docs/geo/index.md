# Geo Blocking

Block or allow requests based on geographic location.

---

## Overview

The geo blocking module allows you to filter requests based on the client's geographic location, including country, continent, and VPN/proxy detection.

## Quick Start

```php
use Lalaz\Waf\Geo\GeoLocation;
use Lalaz\Waf\Geo\Providers\ArrayGeoProvider;
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;

// Allow only US and Canada
$middleware = GeoBlockMiddleware::allowOnly(['US', 'CA']);

// Block specific countries
$middleware = GeoBlockMiddleware::blockOnly(['XX', 'YY']);
```

## GeoLocation

Value object representing geographic information about an IP address.

### Factory Methods

```php
use Lalaz\Waf\Geo\GeoLocation;

// Create from array
$location = GeoLocation::create([
    'country' => 'US',
    'countryName' => 'United States',
    'region' => 'California',
    'city' => 'San Francisco',
    'latitude' => 37.7749,
    'longitude' => -122.4194,
    'isp' => 'Comcast',
    'isProxy' => false,
    'isVpn' => false,
    'isTor' => false,
]);

// Create unknown location
$unknown = GeoLocation::unknown();
```

### Properties

```php
$location->country();     // 'US'
$location->countryName(); // 'United States'
$location->region();      // 'California'
$location->city();        // 'San Francisco'
$location->latitude();    // 37.7749
$location->longitude();   // -122.4194
$location->isp();         // 'Comcast'
$location->isProxy();     // false
$location->isVpn();       // false
$location->isTor();       // false
```

### Methods

```php
// Check if location is known
$location->isKnown();     // true

// Get continent from country
$location->continent();   // 'NA' (North America)

// Convert to array
$location->toArray();
```

## Geo Providers

### GeoProviderInterface

All geo providers implement the `GeoProviderInterface`:

```php
use Lalaz\Waf\Geo\Contracts\GeoProviderInterface;

interface GeoProviderInterface
{
    public function lookup(string $ip): GeoLocation;
}
```

### ArrayGeoProvider

Static array-based provider for testing:

```php
use Lalaz\Waf\Geo\Providers\ArrayGeoProvider;
use Lalaz\Waf\Geo\GeoLocation;

$provider = new ArrayGeoProvider([
    '8.8.8.8' => GeoLocation::create([
        'country' => 'US',
        'countryName' => 'United States',
        'city' => 'Mountain View',
    ]),
    '1.1.1.1' => GeoLocation::create([
        'country' => 'AU',
        'countryName' => 'Australia',
    ]),
]);

$location = $provider->lookup('8.8.8.8');
echo $location->country(); // 'US'
```

### Custom Provider

Create custom providers for production use:

```php
use Lalaz\Waf\Geo\Contracts\GeoProviderInterface;
use Lalaz\Waf\Geo\GeoLocation;

class MaxMindGeoProvider implements GeoProviderInterface
{
    private \GeoIp2\Database\Reader $reader;
    
    public function __construct(string $databasePath)
    {
        $this->reader = new \GeoIp2\Database\Reader($databasePath);
    }
    
    public function lookup(string $ip): GeoLocation
    {
        try {
            $record = $this->reader->city($ip);
            
            return GeoLocation::create([
                'country' => $record->country->isoCode,
                'countryName' => $record->country->name,
                'region' => $record->mostSpecificSubdivision->name,
                'city' => $record->city->name,
                'latitude' => $record->location->latitude,
                'longitude' => $record->location->longitude,
            ]);
        } catch (\Exception $e) {
            return GeoLocation::unknown();
        }
    }
}
```

## GeoBlockMiddleware

Use the middleware for automatic geo blocking:

```php
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;

// Allow only specific countries
$middleware = GeoBlockMiddleware::allowOnly(['US', 'CA', 'GB']);

// Block specific countries
$middleware = GeoBlockMiddleware::blockOnly(['CN', 'RU']);

// Strict mode (block VPN/Proxy/Tor)
$middleware = GeoBlockMiddleware::strict(['US', 'CA']);
```

### Custom Configuration

```php
use Lalaz\Waf\Geo\Providers\MaxMindGeoProvider;

$provider = new MaxMindGeoProvider('/path/to/GeoLite2-City.mmdb');

$middleware = new GeoBlockMiddleware(
    provider: $provider,
    allowedCountries: ['US', 'CA'],
    blockedCountries: [],
    blockVpn: true,
    blockProxy: true,
    blockTor: true,
    onBlock: fn($ip, $location) => Log::warning("Geo blocked: {$ip} ({$location->country()})"),
);
```

## Country Codes

Use ISO 3166-1 alpha-2 country codes:

| Code | Country |
|------|---------|
| US | United States |
| CA | Canada |
| GB | United Kingdom |
| DE | Germany |
| FR | France |
| JP | Japan |
| AU | Australia |
| BR | Brazil |
| IN | India |
| CN | China |

## Continent Codes

| Code | Continent |
|------|-----------|
| AF | Africa |
| AN | Antarctica |
| AS | Asia |
| EU | Europe |
| NA | North America |
| OC | Oceania |
| SA | South America |

## Example: GDPR Compliance

Block users from countries requiring GDPR compliance:

```php
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;

// EU countries requiring GDPR
$euCountries = [
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
    'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
    'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
];

// Block EU for non-GDPR compliant service
$middleware = GeoBlockMiddleware::blockOnly($euCountries);

// Or redirect to GDPR-compliant version
$middleware = new GeoBlockMiddleware(
    provider: $geoProvider,
    blockedCountries: $euCountries,
    onBlock: fn($ip, $location, $request) => redirect('https://eu.example.com' . $request->getUri()->getPath()),
);
```

## Example: Regional Service

```php
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;

// Americas only
$americasMiddleware = GeoBlockMiddleware::allowOnly([
    'US', 'CA', 'MX', 'BR', 'AR', 'CL', 'CO', 'PE',
]);

// Europe only
$europeMiddleware = GeoBlockMiddleware::allowOnly([
    'GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'PT', 'PL',
]);

// Asia-Pacific only
$apacMiddleware = GeoBlockMiddleware::allowOnly([
    'JP', 'KR', 'CN', 'AU', 'NZ', 'SG', 'HK', 'TW', 'IN',
]);
```

## Best Practices

1. **Use a reliable geo database** like MaxMind for production
2. **Update geo databases regularly** (country assignments change)
3. **Handle unknown locations gracefully** (don't block by default)
4. **Consider VPN/proxy users** who may have legitimate reasons
5. **Log geo-blocked requests** for compliance and debugging
6. **Combine with other security measures** (rate limiting, threat detection)

## Next Steps

- [IP Filtering](../ip-filter/index.md) — Filter by IP address
- [Rate Limiting](../rate-limit/index.md) — Request rate limiting
- [Middlewares](../middlewares/index.md) — All available middlewares
