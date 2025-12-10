<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Geo;

use Lalaz\Waf\Geo\GeoLocation;
use PHPUnit\Framework\TestCase;

class GeoLocationTest extends TestCase
{
    public function test_creates_location_with_all_fields(): void
    {
        $location = new GeoLocation(
            countryCode: 'US',
            countryName: 'United States',
            regionCode: 'CA',
            regionName: 'California',
            city: 'San Francisco',
            postalCode: '94102',
            latitude: 37.7749,
            longitude: -122.4194,
            timezone: 'America/Los_Angeles',
            continent: 'NA',
            isp: 'Comcast',
            organization: 'Acme Corp',
            isProxy: false,
            isVpn: false,
            isTor: false,
            isHosting: false,
        );

        $this->assertEquals('US', $location->countryCode);
        $this->assertEquals('United States', $location->countryName);
        $this->assertEquals('CA', $location->regionCode);
        $this->assertEquals('San Francisco', $location->city);
        $this->assertEquals(37.7749, $location->latitude);
        $this->assertEquals(-122.4194, $location->longitude);
        $this->assertEquals('NA', $location->continent);
    }

    public function test_is_in_country(): void
    {
        $location = GeoLocation::forCountry('BR');

        $this->assertTrue($location->isInCountry('BR'));
        $this->assertTrue($location->isInCountry('br')); // Case insensitive
        $this->assertFalse($location->isInCountry('US'));
    }

    public function test_is_in_countries(): void
    {
        $location = GeoLocation::forCountry('BR');

        $this->assertTrue($location->isInCountries(['US', 'BR', 'PT']));
        $this->assertTrue($location->isInCountries(['us', 'br', 'pt'])); // Case insensitive
        $this->assertFalse($location->isInCountries(['US', 'CA', 'MX']));
    }

    public function test_is_in_continent(): void
    {
        $location = new GeoLocation(
            countryCode: 'BR',
            continent: 'SA',
        );

        $this->assertTrue($location->isInContinent('SA'));
        $this->assertTrue($location->isInContinent('sa')); // Case insensitive
        $this->assertFalse($location->isInContinent('NA'));
    }

    public function test_is_anonymized(): void
    {
        $vpn = new GeoLocation(countryCode: 'US', isVpn: true);
        $proxy = new GeoLocation(countryCode: 'US', isProxy: true);
        $tor = new GeoLocation(countryCode: 'US', isTor: true);
        $normal = new GeoLocation(countryCode: 'US', isVpn: false, isProxy: false, isTor: false);

        $this->assertTrue($vpn->isAnonymized());
        $this->assertTrue($proxy->isAnonymized());
        $this->assertTrue($tor->isAnonymized());
        $this->assertFalse($normal->isAnonymized());
    }

    public function test_has_coordinates(): void
    {
        $withCoords = new GeoLocation(latitude: 37.7749, longitude: -122.4194);
        $withoutCoords = new GeoLocation();
        $partialCoords = new GeoLocation(latitude: 37.7749);

        $this->assertTrue($withCoords->hasCoordinates());
        $this->assertFalse($withoutCoords->hasCoordinates());
        $this->assertFalse($partialCoords->hasCoordinates());
    }

    public function test_get_country_code_uppercase(): void
    {
        $location = new GeoLocation(countryCode: 'br');

        $this->assertEquals('BR', $location->getCountryCode());
    }

    public function test_to_array(): void
    {
        $location = new GeoLocation(
            countryCode: 'US',
            countryName: 'United States',
            city: 'New York',
        );

        $array = $location->toArray();

        $this->assertEquals('US', $array['country_code']);
        $this->assertEquals('United States', $array['country_name']);
        $this->assertEquals('New York', $array['city']);
        $this->assertNull($array['region_code']);
    }

    public function test_from_array(): void
    {
        $location = GeoLocation::fromArray([
            'country_code' => 'BR',
            'country_name' => 'Brazil',
            'city' => 'São Paulo',
            'latitude' => -23.5505,
            'longitude' => -46.6333,
        ]);

        $this->assertEquals('BR', $location->countryCode);
        $this->assertEquals('Brazil', $location->countryName);
        $this->assertEquals('São Paulo', $location->city);
        $this->assertEquals(-23.5505, $location->latitude);
    }

    public function test_from_array_with_camel_case(): void
    {
        $location = GeoLocation::fromArray([
            'countryCode' => 'US',
            'countryName' => 'United States',
            'isVpn' => true,
        ]);

        $this->assertEquals('US', $location->countryCode);
        $this->assertTrue($location->isVpn);
    }

    public function test_for_country_factory(): void
    {
        $location = GeoLocation::forCountry('pt', 'Portugal');

        $this->assertEquals('PT', $location->countryCode);
        $this->assertEquals('Portugal', $location->countryName);
    }

    public function test_unknown_factory(): void
    {
        $location = GeoLocation::unknown();

        $this->assertNull($location->countryCode);
        $this->assertNull($location->countryName);
        $this->assertFalse($location->hasCoordinates());
    }
}
