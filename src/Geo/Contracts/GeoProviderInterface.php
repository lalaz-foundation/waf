<?php

declare(strict_types=1);

namespace Lalaz\Waf\Geo\Contracts;

use Lalaz\Waf\Geo\GeoLocation;

/**
 * Interface for GeoIP providers.
 *
 * Implementations can use different GeoIP databases/services:
 * - MaxMind GeoIP2/GeoLite2
 * - IP2Location
 * - ipinfo.io
 * - ipstack
 * - Custom providers
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 */
interface GeoProviderInterface
{
    /**
     * Look up geographic information for an IP address.
     *
     * @param string $ip The IP address to look up.
     * @return GeoLocation|null The location info, or null if not found.
     */
    public function lookup(string $ip): ?GeoLocation;

    /**
     * Get the country code for an IP address.
     *
     * @param string $ip The IP address to look up.
     * @return string|null The ISO 3166-1 alpha-2 country code, or null if not found.
     */
    public function getCountryCode(string $ip): ?string;

    /**
     * Check if the provider is available and configured.
     *
     * @return bool True if the provider can perform lookups.
     */
    public function isAvailable(): bool;

    /**
     * Get the name of the provider.
     *
     * @return string The provider name (e.g., "MaxMind", "IP2Location").
     */
    public function getName(): string;
}
