<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Middlewares;

use PHPUnit\Framework\TestCase;
use Lalaz\Waf\Middlewares\TrustedProxyMiddleware;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;

final class TrustedProxyMiddlewareTest extends TestCase
{
    private function createMiddleware(array $options = []): TrustedProxyMiddleware
    {
        return new TrustedProxyMiddleware(
            trustedProxies: $options['trusted_proxies'] ?? [],
            headers: $options['headers'] ?? [
                TrustedProxyMiddleware::HEADER_CF_CONNECTING_IP,
                TrustedProxyMiddleware::HEADER_TRUE_CLIENT_IP,
                TrustedProxyMiddleware::HEADER_X_REAL_IP,
                TrustedProxyMiddleware::HEADER_X_FORWARDED_FOR,
                TrustedProxyMiddleware::HEADER_X_CLIENT_IP,
                TrustedProxyMiddleware::HEADER_FORWARDED,
            ],
            trustPrivateNetworks: $options['trust_private_networks'] ?? false,
            ipAttribute: $options['ip_attribute'] ?? 'client_ip',
        );
    }

    private function runMiddleware(
        TrustedProxyMiddleware $middleware,
        string $directIp,
        array $headers = [],
    ): ?string {
        $req = new StubRequest(
            httpMethod: 'GET',
            path: '/',
            routeParams: [],
            headers: $headers,
            user: null,
            queryParams: [],
            body: null,
            cookies: [],
            ip: $directIp,
        );
        $res = new StubResponse();
        $resolvedIp = null;

        $middleware->handle($req, $res, function ($req, $res) use (&$resolvedIp) {
            $resolvedIp = $req->getAttribute('client_ip');
        });

        return $resolvedIp;
    }

    // =========================================================================
    // Basic Functionality
    // =========================================================================

    public function test_returns_direct_ip_when_no_trusted_proxies(): void
    {
        $middleware = $this->createMiddleware();
        $ip = $this->runMiddleware($middleware, '203.0.113.50', [
            'X-Forwarded-For' => '1.2.3.4',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_returns_direct_ip_when_not_from_trusted_proxy(): void
    {
        $middleware = $this->createMiddleware([
            'trusted_proxies' => ['10.0.0.0/8'],
        ]);

        $ip = $this->runMiddleware($middleware, '203.0.113.50', [
            'X-Forwarded-For' => '1.2.3.4',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_resolves_ip_from_header_when_from_trusted_proxy(): void
    {
        $middleware = $this->createMiddleware([
            'trusted_proxies' => ['10.0.0.1'],
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_resolves_ip_from_trusted_cidr_range(): void
    {
        $middleware = $this->createMiddleware([
            'trusted_proxies' => ['10.0.0.0/8'],
        ]);

        $ip = $this->runMiddleware($middleware, '10.255.255.255', [
            'X-Forwarded-For' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    // =========================================================================
    // Header Priority
    // =========================================================================

    public function test_cf_connecting_ip_has_highest_priority(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '1.1.1.1',
            'X-Real-IP' => '2.2.2.2',
            'CF-Connecting-IP' => '3.3.3.3',
        ]);

        $this->assertSame('3.3.3.3', $ip);
    }

    public function test_true_client_ip_priority(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '1.1.1.1',
            'X-Real-IP' => '2.2.2.2',
            'True-Client-IP' => '4.4.4.4',
        ]);

        $this->assertSame('4.4.4.4', $ip);
    }

    public function test_x_real_ip_priority_over_x_forwarded_for(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '1.1.1.1',
            'X-Real-IP' => '2.2.2.2',
        ]);

        $this->assertSame('2.2.2.2', $ip);
    }

    public function test_uses_x_forwarded_for_when_no_other_headers(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '5.5.5.5',
        ]);

        $this->assertSame('5.5.5.5', $ip);
    }

    // =========================================================================
    // X-Forwarded-For Parsing
    // =========================================================================

    public function test_x_forwarded_for_returns_leftmost_ip(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '203.0.113.50, 10.0.0.2, 10.0.0.3',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_x_forwarded_for_handles_spaces(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '  203.0.113.50  ,  10.0.0.2  ',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_x_forwarded_for_single_ip(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    // =========================================================================
    // Forwarded Header (RFC 7239)
    // =========================================================================

    public function test_parses_forwarded_header(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
            'headers' => [TrustedProxyMiddleware::HEADER_FORWARDED],
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'Forwarded' => 'for=192.0.2.60;proto=http;by=203.0.113.43',
        ]);

        $this->assertSame('192.0.2.60', $ip);
    }

    public function test_parses_forwarded_header_with_quotes(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
            'headers' => [TrustedProxyMiddleware::HEADER_FORWARDED],
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'Forwarded' => 'for="192.0.2.60";proto=https',
        ]);

        $this->assertSame('192.0.2.60', $ip);
    }

    public function test_parses_forwarded_header_ipv6(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
            'headers' => [TrustedProxyMiddleware::HEADER_FORWARDED],
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'Forwarded' => 'for="[2001:db8::1]";proto=https',
        ]);

        $this->assertSame('2001:db8::1', $ip);
    }

    public function test_forwarded_header_multiple_entries(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
            'headers' => [TrustedProxyMiddleware::HEADER_FORWARDED],
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'Forwarded' => 'for=192.0.2.60, for=198.51.100.178',
        ]);

        $this->assertSame('192.0.2.60', $ip);
    }

    // =========================================================================
    // Trust Private Networks
    // =========================================================================

    public function test_trust_private_networks_trusts_10_range(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Real-IP' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_trust_private_networks_trusts_172_range(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '172.16.0.1', [
            'X-Real-IP' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_trust_private_networks_trusts_192_168_range(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '192.168.1.1', [
            'X-Real-IP' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_trust_private_networks_trusts_localhost(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '127.0.0.1', [
            'X-Real-IP' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    // =========================================================================
    // Factory Methods
    // =========================================================================

    public function test_for_cloudflare_trusts_cloudflare_ips(): void
    {
        $middleware = TrustedProxyMiddleware::forCloudflare();

        // Use a Cloudflare IP from the first range
        $ip = $this->runMiddleware($middleware, '173.245.48.1', [
            'CF-Connecting-IP' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_for_cloudflare_ignores_non_cloudflare_ips(): void
    {
        $middleware = TrustedProxyMiddleware::forCloudflare();

        $ip = $this->runMiddleware($middleware, '1.2.3.4', [
            'CF-Connecting-IP' => '203.0.113.50',
        ]);

        $this->assertSame('1.2.3.4', $ip);
    }

    public function test_for_nginx_trusts_private_networks(): void
    {
        $middleware = TrustedProxyMiddleware::forNginx();

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Real-IP' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_for_nginx_uses_x_real_ip_priority(): void
    {
        $middleware = TrustedProxyMiddleware::forNginx();

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '1.1.1.1',
            'X-Real-IP' => '2.2.2.2',
        ]);

        $this->assertSame('2.2.2.2', $ip);
    }

    public function test_for_aws_alb_trusts_private_networks(): void
    {
        $middleware = TrustedProxyMiddleware::forAwsAlb();

        $ip = $this->runMiddleware($middleware, '172.31.0.1', [
            'X-Forwarded-For' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_for_development_trusts_everything(): void
    {
        $middleware = TrustedProxyMiddleware::forDevelopment();

        $ip = $this->runMiddleware($middleware, '192.168.1.1', [
            'X-Forwarded-For' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    // =========================================================================
    // Configuration
    // =========================================================================

    public function test_from_config(): void
    {
        $middleware = TrustedProxyMiddleware::fromConfig([
            'trusted_proxies' => ['10.0.0.1'],
            'headers' => ['X-Real-IP'],
            'trust_private_networks' => false,
            'ip_attribute' => 'real_ip',
        ]);

        $req = new StubRequest(
            httpMethod: 'GET',
            path: '/',
            headers: ['X-Real-IP' => '203.0.113.50'],
            ip: '10.0.0.1',
        );
        $res = new StubResponse();
        $resolvedIp = null;

        $middleware->handle($req, $res, function ($req, $res) use (&$resolvedIp) {
            $resolvedIp = $req->getAttribute('real_ip');
        });

        $this->assertSame('203.0.113.50', $resolvedIp);
    }

    public function test_custom_ip_attribute(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
            'ip_attribute' => 'real_client_ip',
        ]);

        $req = new StubRequest('GET', '/', [], ['X-Real-IP' => '203.0.113.50'], null, null, '10.0.0.1');
        $res = new StubResponse();
        $resolvedIp = null;

        $middleware->handle($req, $res, function ($req, $res) use (&$resolvedIp) {
            $resolvedIp = $req->getAttribute('real_client_ip');
        });

        $this->assertSame('203.0.113.50', $resolvedIp);
    }

    public function test_null_ip_attribute_does_not_set_attribute(): void
    {
        $middleware = new TrustedProxyMiddleware(
            trustedProxies: ['10.0.0.1'],
            headers: ['X-Real-IP'],
            trustPrivateNetworks: false,
            ipAttribute: null,
        );

        $req = new StubRequest('GET', '/', [], ['X-Real-IP' => '203.0.113.50'], null, null, '10.0.0.1');
        $res = new StubResponse();
        $clientIp = 'not-set';

        $middleware->handle($req, $res, function ($req, $res) use (&$clientIp) {
            $clientIp = $req->getAttribute('client_ip') ?? 'not-set';
        });

        $this->assertSame('not-set', $clientIp);
    }

    // =========================================================================
    // Immutable Setters
    // =========================================================================

    public function test_with_trusted_proxies_adds_proxies(): void
    {
        $middleware = $this->createMiddleware([
            'trusted_proxies' => ['10.0.0.1'],
        ])->withTrustedProxies(['10.0.0.2']);

        $ip = $this->runMiddleware($middleware, '10.0.0.2', [
            'X-Real-IP' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_with_headers_changes_priority(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ])->withHeaders(['X-Forwarded-For', 'X-Real-IP']);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Forwarded-For' => '1.1.1.1',
            'X-Real-IP' => '2.2.2.2',
        ]);

        $this->assertSame('1.1.1.1', $ip);
    }

    public function test_trust_private_networks_method(): void
    {
        $middleware = $this->createMiddleware()->trustPrivateNetworks();

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Real-IP' => '203.0.113.50',
        ]);

        $this->assertSame('203.0.113.50', $ip);
    }

    public function test_with_resolver(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ])->withResolver(fn($req) => 'custom.ip.from.resolver');

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Real-IP' => '203.0.113.50',
        ]);

        $this->assertSame('custom.ip.from.resolver', $ip);
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    public function test_get_cloudflare_ips_v4(): void
    {
        $ips = TrustedProxyMiddleware::getCloudflareIpsV4();

        $this->assertNotEmpty($ips);
        $this->assertContains('173.245.48.0/20', $ips);
    }

    public function test_get_cloudflare_ips_v6(): void
    {
        $ips = TrustedProxyMiddleware::getCloudflareIpsV6();

        $this->assertNotEmpty($ips);
        $this->assertContains('2400:cb00::/32', $ips);
    }

    public function test_get_cloudflare_ips_all(): void
    {
        $ips = TrustedProxyMiddleware::getCloudflareIps();

        $this->assertNotEmpty($ips);
        $this->assertContains('173.245.48.0/20', $ips);
        $this->assertContains('2400:cb00::/32', $ips);
    }

    public function test_get_private_ranges(): void
    {
        $ranges = TrustedProxyMiddleware::getPrivateRanges();

        $this->assertNotEmpty($ranges);
        $this->assertContains('10.0.0.0/8', $ranges);
        $this->assertContains('172.16.0.0/12', $ranges);
        $this->assertContains('192.168.0.0/16', $ranges);
        $this->assertContains('127.0.0.0/8', $ranges);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    public function test_empty_header_value_falls_back_to_direct_ip(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Real-IP' => '',
        ]);

        $this->assertSame('10.0.0.1', $ip);
    }

    public function test_invalid_ip_in_header_falls_back(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
            'headers' => ['X-Real-IP'],
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', [
            'X-Real-IP' => 'not-an-ip',
        ]);

        $this->assertSame('10.0.0.1', $ip);
    }

    public function test_no_headers_returns_direct_ip(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '10.0.0.1', []);

        $this->assertSame('10.0.0.1', $ip);
    }

    public function test_handles_ipv6_addresses(): void
    {
        $middleware = $this->createMiddleware([
            'trust_private_networks' => true,
        ]);

        $ip = $this->runMiddleware($middleware, '::1', [
            'X-Real-IP' => '2001:db8::1',
        ]);

        $this->assertSame('2001:db8::1', $ip);
    }
}
