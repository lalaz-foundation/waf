<?php

declare(strict_types=1);

namespace Lalaz\Waf\Geo\Providers;

use Lalaz\Waf\Geo\Contracts\GeoProviderInterface;
use Lalaz\Waf\Geo\GeoLocation;

/**
 * In-memory GeoIP provider for testing and simple use cases.
 *
 * Maps IP addresses or CIDR ranges to country codes.
 *
 * @example
 * ```php
 * $provider = new ArrayGeoProvider([
 *     '192.168.1.0/24' => 'US',
 *     '10.0.0.0/8' => 'BR',
 *     '8.8.8.8' => 'US',
 * ]);
 *
 * $provider->getCountryCode('192.168.1.50'); // 'US'
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 */
class ArrayGeoProvider implements GeoProviderInterface
{
    /**
     * @var array<string, string|GeoLocation> IP to country/location mapping.
     */
    private array $mappings = [];

    /**
     * @var string|null Default country code for unknown IPs.
     */
    private ?string $defaultCountry;

    /**
     * Create a new array geo provider.
     *
     * @param array<string, string|GeoLocation|array<string, mixed>> $mappings IP/CIDR to country/location.
     * @param string|null $defaultCountry Default country for unknown IPs.
     */
    public function __construct(
        array $mappings = [],
        ?string $defaultCountry = null,
    ) {
        foreach ($mappings as $ip => $value) {
            $this->addMapping($ip, $value);
        }
        $this->defaultCountry = $defaultCountry;
    }

    /**
     * Add a mapping.
     *
     * @param string $ip IP address or CIDR range.
     * @param string|GeoLocation|array<string, mixed> $value Country code, GeoLocation, or location array.
     * @return self
     */
    public function addMapping(string $ip, string|GeoLocation|array $value): self
    {
        if (is_string($value)) {
            $this->mappings[$ip] = GeoLocation::forCountry($value);
        } elseif (is_array($value)) {
            $this->mappings[$ip] = GeoLocation::fromArray($value);
        } else {
            $this->mappings[$ip] = $value;
        }

        return $this;
    }

    /**
     * Add multiple mappings.
     *
     * @param array<string, string|GeoLocation|array<string, mixed>> $mappings
     * @return self
     */
    public function addMappings(array $mappings): self
    {
        foreach ($mappings as $ip => $value) {
            $this->addMapping($ip, $value);
        }
        return $this;
    }

    /**
     * Set the default country for unknown IPs.
     *
     * @param string|null $countryCode
     * @return self
     */
    public function setDefault(?string $countryCode): self
    {
        $this->defaultCountry = $countryCode;
        return $this;
    }

    /**
     * @inheritDoc
     */
    public function lookup(string $ip): ?GeoLocation
    {
        // Try exact match first
        if (isset($this->mappings[$ip])) {
            return $this->mappings[$ip];
        }

        // Try CIDR matches
        foreach ($this->mappings as $pattern => $location) {
            if ($this->matchesCidr($ip, $pattern)) {
                return $location;
            }
        }

        // Return default if set
        if ($this->defaultCountry !== null) {
            return GeoLocation::forCountry($this->defaultCountry);
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public function getCountryCode(string $ip): ?string
    {
        $location = $this->lookup($ip);
        return $location?->getCountryCode();
    }

    /**
     * @inheritDoc
     */
    public function isAvailable(): bool
    {
        return true;
    }

    /**
     * @inheritDoc
     */
    public function getName(): string
    {
        return 'ArrayGeoProvider';
    }

    /**
     * Check if an IP matches a CIDR pattern.
     *
     * @param string $ip
     * @param string $cidr
     * @return bool
     */
    private function matchesCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $mask = -1 << (32 - $bits);

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    /**
     * Create a provider with common private IP mappings.
     *
     * @param string $countryCode Country code to assign to private IPs.
     * @return self
     */
    public static function withPrivateIps(string $countryCode = 'XX'): self
    {
        return new self([
            '10.0.0.0/8' => $countryCode,
            '172.16.0.0/12' => $countryCode,
            '192.168.0.0/16' => $countryCode,
            '127.0.0.0/8' => $countryCode,
        ]);
    }

    /**
     * Create an empty provider.
     *
     * @return self
     */
    public static function empty(): self
    {
        return new self();
    }
}
