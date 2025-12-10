<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Geo;

use Lalaz\Waf\Geo\GeoLocation;
use Lalaz\Waf\Geo\Providers\ArrayGeoProvider;
use PHPUnit\Framework\TestCase;

class ArrayGeoProviderTest extends TestCase
{
    public function test_lookup_exact_match(): void
    {
        $provider = new ArrayGeoProvider([
            '8.8.8.8' => 'US',
            '1.1.1.1' => 'AU',
        ]);

        $location = $provider->lookup('8.8.8.8');

        $this->assertNotNull($location);
        $this->assertEquals('US', $location->countryCode);
    }

    public function test_lookup_cidr_match(): void
    {
        $provider = new ArrayGeoProvider([
            '192.168.1.0/24' => 'BR',
        ]);

        $location = $provider->lookup('192.168.1.50');

        $this->assertNotNull($location);
        $this->assertEquals('BR', $location->countryCode);
    }

    public function test_lookup_returns_null_for_unknown(): void
    {
        $provider = new ArrayGeoProvider([
            '8.8.8.8' => 'US',
        ]);

        $location = $provider->lookup('1.2.3.4');

        $this->assertNull($location);
    }

    public function test_lookup_with_default_country(): void
    {
        $provider = new ArrayGeoProvider(
            mappings: ['8.8.8.8' => 'US'],
            defaultCountry: 'XX',
        );

        $location = $provider->lookup('1.2.3.4');

        $this->assertNotNull($location);
        $this->assertEquals('XX', $location->countryCode);
    }

    public function test_get_country_code(): void
    {
        $provider = new ArrayGeoProvider([
            '8.8.8.8' => 'US',
        ]);

        $this->assertEquals('US', $provider->getCountryCode('8.8.8.8'));
        $this->assertNull($provider->getCountryCode('1.2.3.4'));
    }

    public function test_add_mapping(): void
    {
        $provider = ArrayGeoProvider::empty()
            ->addMapping('8.8.8.8', 'US')
            ->addMapping('1.1.1.1', 'AU');

        $this->assertEquals('US', $provider->getCountryCode('8.8.8.8'));
        $this->assertEquals('AU', $provider->getCountryCode('1.1.1.1'));
    }

    public function test_add_mapping_with_geo_location(): void
    {
        $provider = ArrayGeoProvider::empty()
            ->addMapping('8.8.8.8', new GeoLocation(
                countryCode: 'US',
                countryName: 'United States',
                city: 'Mountain View',
            ));

        $location = $provider->lookup('8.8.8.8');

        $this->assertEquals('US', $location->countryCode);
        $this->assertEquals('Mountain View', $location->city);
    }

    public function test_add_mapping_with_array(): void
    {
        $provider = ArrayGeoProvider::empty()
            ->addMapping('8.8.8.8', [
                'country_code' => 'US',
                'country_name' => 'United States',
                'is_vpn' => true,
            ]);

        $location = $provider->lookup('8.8.8.8');

        $this->assertEquals('US', $location->countryCode);
        $this->assertTrue($location->isVpn);
    }

    public function test_add_mappings(): void
    {
        $provider = ArrayGeoProvider::empty()
            ->addMappings([
                '8.8.8.8' => 'US',
                '1.1.1.1' => 'AU',
                '8.8.4.4' => 'US',
            ]);

        $this->assertEquals('US', $provider->getCountryCode('8.8.8.8'));
        $this->assertEquals('AU', $provider->getCountryCode('1.1.1.1'));
    }

    public function test_set_default(): void
    {
        $provider = ArrayGeoProvider::empty()
            ->setDefault('ZZ');

        $this->assertEquals('ZZ', $provider->getCountryCode('1.2.3.4'));
    }

    public function test_is_available(): void
    {
        $provider = new ArrayGeoProvider();

        $this->assertTrue($provider->isAvailable());
    }

    public function test_get_name(): void
    {
        $provider = new ArrayGeoProvider();

        $this->assertEquals('ArrayGeoProvider', $provider->getName());
    }

    public function test_with_private_ips_factory(): void
    {
        $provider = ArrayGeoProvider::withPrivateIps('XX');

        $this->assertEquals('XX', $provider->getCountryCode('10.0.0.1'));
        $this->assertEquals('XX', $provider->getCountryCode('172.16.0.1'));
        $this->assertEquals('XX', $provider->getCountryCode('192.168.1.1'));
        $this->assertEquals('XX', $provider->getCountryCode('127.0.0.1'));
    }

    public function test_cidr_priority_over_exact(): void
    {
        // Exact match should take priority
        $provider = new ArrayGeoProvider([
            '192.168.1.50' => 'BR',
            '192.168.1.0/24' => 'US',
        ]);

        $this->assertEquals('BR', $provider->getCountryCode('192.168.1.50'));
        $this->assertEquals('US', $provider->getCountryCode('192.168.1.100'));
    }
}
