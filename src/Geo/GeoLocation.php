<?php

declare(strict_types=1);

namespace Lalaz\Waf\Geo;

/**
 * Geographic location information for an IP address.
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 */
final class GeoLocation
{
    /**
     * Create a new GeoLocation instance.
     *
     * @param string|null $countryCode ISO 3166-1 alpha-2 country code (e.g., "US", "BR").
     * @param string|null $countryName Full country name (e.g., "United States", "Brazil").
     * @param string|null $regionCode State/province code (e.g., "CA", "SP").
     * @param string|null $regionName State/province name (e.g., "California", "São Paulo").
     * @param string|null $city City name.
     * @param string|null $postalCode Postal/ZIP code.
     * @param float|null $latitude Latitude coordinate.
     * @param float|null $longitude Longitude coordinate.
     * @param string|null $timezone Timezone identifier (e.g., "America/New_York").
     * @param string|null $continent Continent code (e.g., "NA", "SA", "EU").
     * @param string|null $isp Internet Service Provider name.
     * @param string|null $organization Organization name.
     * @param bool|null $isProxy Whether the IP is a known proxy.
     * @param bool|null $isVpn Whether the IP is a known VPN.
     * @param bool|null $isTor Whether the IP is a known Tor exit node.
     * @param bool|null $isHosting Whether the IP belongs to a hosting provider.
     */
    public function __construct(
        public readonly ?string $countryCode = null,
        public readonly ?string $countryName = null,
        public readonly ?string $regionCode = null,
        public readonly ?string $regionName = null,
        public readonly ?string $city = null,
        public readonly ?string $postalCode = null,
        public readonly ?float $latitude = null,
        public readonly ?float $longitude = null,
        public readonly ?string $timezone = null,
        public readonly ?string $continent = null,
        public readonly ?string $isp = null,
        public readonly ?string $organization = null,
        public readonly ?bool $isProxy = null,
        public readonly ?bool $isVpn = null,
        public readonly ?bool $isTor = null,
        public readonly ?bool $isHosting = null,
    ) {
    }

    /**
     * Check if the location is in a specific country.
     *
     * @param string $countryCode ISO 3166-1 alpha-2 country code.
     * @return bool True if the location matches the country.
     */
    public function isInCountry(string $countryCode): bool
    {
        return strtoupper($this->countryCode ?? '') === strtoupper($countryCode);
    }

    /**
     * Check if the location is in any of the specified countries.
     *
     * @param array<string> $countryCodes List of ISO 3166-1 alpha-2 country codes.
     * @return bool True if the location matches any country.
     */
    public function isInCountries(array $countryCodes): bool
    {
        $normalizedCodes = array_map('strtoupper', $countryCodes);
        return in_array(strtoupper($this->countryCode ?? ''), $normalizedCodes, true);
    }

    /**
     * Check if the location is in a specific continent.
     *
     * @param string $continentCode Continent code (AF, AN, AS, EU, NA, OC, SA).
     * @return bool True if the location matches the continent.
     */
    public function isInContinent(string $continentCode): bool
    {
        return strtoupper($this->continent ?? '') === strtoupper($continentCode);
    }

    /**
     * Check if the IP appears to be anonymized (proxy, VPN, or Tor).
     *
     * @return bool True if the IP is likely anonymized.
     */
    public function isAnonymized(): bool
    {
        return $this->isProxy === true
            || $this->isVpn === true
            || $this->isTor === true;
    }

    /**
     * Check if coordinates are available.
     *
     * @return bool True if latitude and longitude are set.
     */
    public function hasCoordinates(): bool
    {
        return $this->latitude !== null && $this->longitude !== null;
    }

    /**
     * Get the country code in uppercase.
     *
     * @return string|null The country code or null.
     */
    public function getCountryCode(): ?string
    {
        return $this->countryCode !== null ? strtoupper($this->countryCode) : null;
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'country_code' => $this->countryCode,
            'country_name' => $this->countryName,
            'region_code' => $this->regionCode,
            'region_name' => $this->regionName,
            'city' => $this->city,
            'postal_code' => $this->postalCode,
            'latitude' => $this->latitude,
            'longitude' => $this->longitude,
            'timezone' => $this->timezone,
            'continent' => $this->continent,
            'isp' => $this->isp,
            'organization' => $this->organization,
            'is_proxy' => $this->isProxy,
            'is_vpn' => $this->isVpn,
            'is_tor' => $this->isTor,
            'is_hosting' => $this->isHosting,
        ];
    }

    /**
     * Create from array.
     *
     * @param array<string, mixed> $data
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            countryCode: $data['country_code'] ?? $data['countryCode'] ?? null,
            countryName: $data['country_name'] ?? $data['countryName'] ?? null,
            regionCode: $data['region_code'] ?? $data['regionCode'] ?? null,
            regionName: $data['region_name'] ?? $data['regionName'] ?? null,
            city: $data['city'] ?? null,
            postalCode: $data['postal_code'] ?? $data['postalCode'] ?? null,
            latitude: isset($data['latitude']) ? (float) $data['latitude'] : null,
            longitude: isset($data['longitude']) ? (float) $data['longitude'] : null,
            timezone: $data['timezone'] ?? null,
            continent: $data['continent'] ?? null,
            isp: $data['isp'] ?? null,
            organization: $data['organization'] ?? null,
            isProxy: $data['is_proxy'] ?? $data['isProxy'] ?? null,
            isVpn: $data['is_vpn'] ?? $data['isVpn'] ?? null,
            isTor: $data['is_tor'] ?? $data['isTor'] ?? null,
            isHosting: $data['is_hosting'] ?? $data['isHosting'] ?? null,
        );
    }

    /**
     * Create a location with just country information.
     *
     * @param string $countryCode ISO 3166-1 alpha-2 country code.
     * @param string|null $countryName Optional country name.
     * @return self
     */
    public static function forCountry(string $countryCode, ?string $countryName = null): self
    {
        return new self(
            countryCode: strtoupper($countryCode),
            countryName: $countryName,
        );
    }

    /**
     * Create an unknown/empty location.
     *
     * @return self
     */
    public static function unknown(): self
    {
        return new self();
    }
}
