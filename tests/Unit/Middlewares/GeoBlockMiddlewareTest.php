<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Middlewares;

use Lalaz\Waf\Geo\GeoLocation;
use Lalaz\Waf\Geo\Providers\ArrayGeoProvider;
use Lalaz\Waf\Middlewares\GeoBlockMiddleware;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

class GeoBlockMiddlewareTest extends TestCase
{
    private ArrayGeoProvider $geoProvider;

    protected function setUp(): void
    {
        $this->geoProvider = new ArrayGeoProvider([
            '1.0.0.1' => 'US',
            '2.0.0.1' => 'BR',
            '3.0.0.1' => 'CN',
            '4.0.0.1' => 'RU',
            '5.0.0.1' => new GeoLocation(
                countryCode: 'US',
                continent: 'NA',
            ),
            '6.0.0.1' => new GeoLocation(
                countryCode: 'DE',
                continent: 'EU',
            ),
            '7.0.0.1' => new GeoLocation(
                countryCode: 'US',
                isVpn: true,
            ),
            '8.0.0.1' => new GeoLocation(
                countryCode: 'US',
                isProxy: true,
            ),
            '9.0.0.1' => new GeoLocation(
                countryCode: 'US',
                isTor: true,
            ),
            '10.0.0.1' => new GeoLocation(
                countryCode: 'US',
                isHosting: true,
            ),
        ]);
    }

    // ========================================
    // Allowlist Tests
    // ========================================

    public function test_allows_request_from_allowed_country(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US', 'BR'], $this->geoProvider);
        $request = $this->createRequest('1.0.0.1'); // US
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_from_non_allowed_country(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US', 'BR'], $this->geoProvider);
        $request = $this->createRequest('3.0.0.1'); // CN
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(403, $response->getStatusCode());
    }

    // ========================================
    // Blocklist Tests
    // ========================================

    public function test_allows_request_from_non_blocked_country(): void
    {
        $middleware = GeoBlockMiddleware::blockOnly(['CN', 'RU'], $this->geoProvider);
        $request = $this->createRequest('1.0.0.1'); // US
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_from_blocked_country(): void
    {
        $middleware = GeoBlockMiddleware::blockOnly(['CN', 'RU'], $this->geoProvider);
        $request = $this->createRequest('3.0.0.1'); // CN
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(403, $response->getStatusCode());
    }

    // ========================================
    // Continent Tests
    // ========================================

    public function test_allows_request_from_allowed_continent(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->allowContinents(['NA', 'SA']);

        $request = $this->createRequest('5.0.0.1'); // US, NA
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_from_non_allowed_continent(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->allowContinents(['NA', 'SA']);

        $request = $this->createRequest('6.0.0.1'); // DE, EU
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_blocks_request_from_blocked_continent(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->blockContinents(['EU']);

        $request = $this->createRequest('6.0.0.1'); // DE, EU
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    // ========================================
    // Unknown Location Tests
    // ========================================

    public function test_allows_unknown_location_by_default(): void
    {
        $middleware = GeoBlockMiddleware::blockOnly(['CN'], $this->geoProvider);
        $request = $this->createRequest('99.99.99.99'); // Unknown
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_unknown_location_when_configured(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->blockCountries(['CN'])
            ->blockUnknown(true);

        $request = $this->createRequest('99.99.99.99'); // Unknown
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_blocks_unknown_location_with_allowlist(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US', 'BR'], $this->geoProvider);
        $request = $this->createRequest('99.99.99.99'); // Unknown
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    // ========================================
    // Anonymized IP Tests
    // ========================================

    public function test_allows_vpn_by_default(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->allowCountries(['US']);

        $request = $this->createRequest('7.0.0.1'); // US with VPN
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_vpn_when_configured(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->allowCountries(['US'])
            ->blockAnonymized(true);

        $request = $this->createRequest('7.0.0.1'); // US with VPN
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_blocks_proxy_when_configured(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->blockAnonymized(true);

        $request = $this->createRequest('8.0.0.1'); // US with Proxy
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_blocks_tor_when_configured(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->blockAnonymized(true);

        $request = $this->createRequest('9.0.0.1'); // US with Tor
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    // ========================================
    // Hosting IP Tests
    // ========================================

    public function test_allows_hosting_by_default(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->allowCountries(['US']);

        $request = $this->createRequest('10.0.0.1'); // US hosting
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_hosting_when_configured(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->allowCountries(['US'])
            ->blockHosting(true);

        $request = $this->createRequest('10.0.0.1'); // US hosting
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    // ========================================
    // IP Whitelist Tests
    // ========================================

    public function test_whitelisted_ip_bypasses_geo_check(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US'], $this->geoProvider)
            ->whitelistIps(['3.0.0.1']); // CN but whitelisted

        $request = $this->createRequest('3.0.0.1');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    // ========================================
    // Custom Handler Tests
    // ========================================

    public function test_custom_block_handler(): void
    {
        $capturedReason = null;
        $capturedLocation = null;

        $middleware = GeoBlockMiddleware::allowOnly(['US'], $this->geoProvider)
            ->onBlock(function ($req, $res, $ip, $location, $reason) use (&$capturedReason, &$capturedLocation) {
                $capturedReason = $reason;
                $capturedLocation = $location;
                $res->json(['custom' => 'blocked'], 451);
            });

        $request = $this->createRequest('3.0.0.1'); // CN
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('not_in_allowed_country', $capturedReason);
        $this->assertEquals('CN', $capturedLocation->countryCode);
        $this->assertEquals(451, $response->getStatusCode());
    }

    public function test_on_check_handler(): void
    {
        $capturedIp = null;
        $capturedLocation = null;

        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->onCheck(function ($ip, $location, $req) use (&$capturedIp, &$capturedLocation) {
                $capturedIp = $ip;
                $capturedLocation = $location;
            });

        $request = $this->createRequest('1.0.0.1');
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('1.0.0.1', $capturedIp);
        $this->assertEquals('US', $capturedLocation->countryCode);
    }

    // ========================================
    // Trust Proxy Tests
    // ========================================

    public function test_uses_direct_ip_by_default(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US'], $this->geoProvider);
        $request = $this->createRequest('1.0.0.1', [
            'X-Forwarded-For' => '3.0.0.1', // CN
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // Uses direct IP (US)
    }

    public function test_uses_forwarded_ip_when_trust_proxy(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US'], $this->geoProvider)
            ->trustProxy(true);

        $request = $this->createRequest('1.0.0.1', [
            'X-Forwarded-For' => '3.0.0.1', // CN
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called); // Uses forwarded IP (CN)
    }

    public function test_custom_ip_resolver(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US'], $this->geoProvider)
            ->setIpResolver(fn($req) => '3.0.0.1'); // Always return CN

        $request = $this->createRequest('1.0.0.1'); // US
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called); // Custom resolver returns CN
    }

    // ========================================
    // Factory Methods Tests
    // ========================================

    public function test_allow_only_factory(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US', 'CA'], $this->geoProvider);

        $this->assertEquals(['US', 'CA'], $middleware->getAllowedCountries());
    }

    public function test_block_only_factory(): void
    {
        $middleware = GeoBlockMiddleware::blockOnly(['CN', 'RU'], $this->geoProvider);

        $this->assertEquals(['CN', 'RU'], $middleware->getBlockedCountries());
    }

    public function test_strict_factory(): void
    {
        $middleware = GeoBlockMiddleware::strict(['US'], $this->geoProvider);

        // Test unknown is blocked
        $request = $this->createRequest('99.99.99.99');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_from_config(): void
    {
        $middleware = GeoBlockMiddleware::fromConfig([
            'allowed_countries' => ['US', 'BR'],
            'blocked_countries' => ['CN'],
            'block_unknown' => true,
            'block_anonymized' => true,
            'trust_proxy' => true,
        ], $this->geoProvider);

        $this->assertEquals(['US', 'BR'], $middleware->getAllowedCountries());
        $this->assertEquals(['CN'], $middleware->getBlockedCountries());
    }

    // ========================================
    // Utility Methods Tests
    // ========================================

    public function test_would_allow_country(): void
    {
        $middleware = GeoBlockMiddleware::allowOnly(['US', 'BR'], $this->geoProvider);

        $this->assertTrue($middleware->wouldAllowCountry('US'));
        $this->assertTrue($middleware->wouldAllowCountry('BR'));
        $this->assertFalse($middleware->wouldAllowCountry('CN'));
    }

    public function test_get_geo_provider(): void
    {
        $middleware = new GeoBlockMiddleware($this->geoProvider);

        $this->assertSame($this->geoProvider, $middleware->getGeoProvider());
    }

    // ========================================
    // Case Insensitivity Tests
    // ========================================

    public function test_country_codes_are_case_insensitive(): void
    {
        $middleware = (new GeoBlockMiddleware($this->geoProvider))
            ->allowCountries(['us', 'br']);

        $request = $this->createRequest('1.0.0.1'); // US
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    // ========================================
    // Helper Methods
    // ========================================

    private function createRequest(string $ip, array $headers = []): StubRequest
    {
        return new StubRequest(
            httpMethod: 'GET',
            path: '/',
            headers: $headers,
            ip: $ip,
        );
    }
}
