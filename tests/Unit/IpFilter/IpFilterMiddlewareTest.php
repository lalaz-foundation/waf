<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\IpFilter;

use Lalaz\Waf\Middlewares\IpFilterMiddleware;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

class IpFilterMiddlewareTest extends TestCase
{
    public function test_whitelist_only_allows_whitelisted_ips(): void
    {
        $middleware = IpFilterMiddleware::whitelist(['192.168.1.1', '192.168.1.2']);
        $request = StubRequest::create(ip: '192.168.1.1');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_whitelist_only_blocks_non_whitelisted_ips(): void
    {
        $middleware = IpFilterMiddleware::whitelist(['192.168.1.1']);
        $request = StubRequest::create(ip: '192.168.1.100');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_blacklist_only_blocks_blacklisted_ips(): void
    {
        $middleware = IpFilterMiddleware::blacklist(['192.168.1.100']);
        $request = StubRequest::create(ip: '192.168.1.100');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_blacklist_only_allows_non_blacklisted_ips(): void
    {
        $middleware = IpFilterMiddleware::blacklist(['192.168.1.100']);
        $request = StubRequest::create(ip: '192.168.1.1');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_whitelist_overrides_deny_by_default(): void
    {
        // Create middleware with deny by default + whitelist
        $middleware = new IpFilterMiddleware(
            whitelist: ['192.168.1.1'],
            blacklist: [],
            denyByDefault: true,
        );
        $request = StubRequest::create(ip: '192.168.1.1');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_whitelist_bypasses_blacklist(): void
    {
        // Same IP on both lists - whitelist should win
        $middleware = new IpFilterMiddleware(
            whitelist: ['192.168.1.1'],
            blacklist: ['192.168.1.1'],
            denyByDefault: false,
        );
        $request = StubRequest::create(ip: '192.168.1.1');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_cidr_range_matching_in_blacklist(): void
    {
        $middleware = IpFilterMiddleware::blacklist(['192.168.0.0/16']);
        $request = StubRequest::create(ip: '192.168.100.50');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_cidr_range_matching_in_whitelist(): void
    {
        $middleware = IpFilterMiddleware::whitelist(['10.0.0.0/8']);
        $request = StubRequest::create(ip: '10.50.100.200');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_whitelist_factory_method(): void
    {
        $middleware = IpFilterMiddleware::whitelist(['192.168.1.1', '10.0.0.0/8']);

        $this->assertInstanceOf(IpFilterMiddleware::class, $middleware);
        $this->assertTrue($middleware->wouldAllow('192.168.1.1'));
        $this->assertFalse($middleware->wouldAllow('1.2.3.4'));
    }

    public function test_blacklist_factory_method(): void
    {
        $middleware = IpFilterMiddleware::blacklist(['192.168.1.100', '172.16.0.0/12']);

        $this->assertInstanceOf(IpFilterMiddleware::class, $middleware);
        $this->assertFalse($middleware->wouldAllow('192.168.1.100'));
        $this->assertTrue($middleware->wouldAllow('1.2.3.4'));
    }

    public function test_from_config_factory(): void
    {
        $config = [
            'whitelist' => ['192.168.1.1', '192.168.1.2'],
            'blacklist' => ['10.0.0.0/8'],
            'deny_by_default' => false,
        ];

        $middleware = IpFilterMiddleware::fromConfig($config);

        $this->assertInstanceOf(IpFilterMiddleware::class, $middleware);
    }

    public function test_from_config_with_defaults(): void
    {
        $config = [
            'blacklist' => ['192.168.1.100'],
        ];

        $middleware = IpFilterMiddleware::fromConfig($config);

        $this->assertInstanceOf(IpFilterMiddleware::class, $middleware);
        $this->assertFalse($middleware->wouldAllow('192.168.1.100'));
    }

    public function test_empty_blacklist_allows_all(): void
    {
        $middleware = IpFilterMiddleware::blacklist([]);
        $request = StubRequest::create(ip: '192.168.1.1');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_wildcard_pattern_in_blacklist(): void
    {
        $middleware = IpFilterMiddleware::blacklist(['192.168.1.*']);

        // Should block
        $request1 = StubRequest::create(ip: '192.168.1.50');
        $response1 = new StubResponse();
        $called1 = false;
        $middleware->handle($request1, $response1, function () use (&$called1) {
            $called1 = true;
        });

        // Should allow
        $request2 = StubRequest::create(ip: '192.168.2.50');
        $response2 = new StubResponse();
        $called2 = false;
        $middleware->handle($request2, $response2, function () use (&$called2) {
            $called2 = true;
        });

        $this->assertFalse($called1);
        $this->assertTrue($called2);
    }

    public function test_allow_and_block_fluent_methods(): void
    {
        $middleware = IpFilterMiddleware::create()
            ->allow(['192.168.1.1'])
            ->block(['10.0.0.0/8']);

        $this->assertTrue($middleware->wouldAllow('192.168.1.1'));
        $this->assertFalse($middleware->wouldAllow('10.50.0.1'));
    }

    public function test_deny_by_default_method(): void
    {
        $middleware = IpFilterMiddleware::create()
            ->allow(['192.168.1.1'])
            ->denyByDefault();

        $this->assertTrue($middleware->wouldAllow('192.168.1.1'));
        $this->assertFalse($middleware->wouldAllow('1.2.3.4'));
    }

    public function test_custom_on_block_handler(): void
    {
        $customMessage = null;

        $middleware = IpFilterMiddleware::blacklist(['192.168.1.100'])
            ->onBlock(function ($req, $res, $ip, $reason) use (&$customMessage) {
                $customMessage = "Blocked: $ip ($reason)";
                $res->json(['blocked' => true], 403);
            });

        $request = StubRequest::create(ip: '192.168.1.100');
        $response = new StubResponse();
        $middleware->handle($request, $response, function () {});

        $this->assertEquals('Blocked: 192.168.1.100 (blacklisted)', $customMessage);
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_custom_ip_resolver(): void
    {
        $middleware = IpFilterMiddleware::whitelist(['10.0.0.1'])
            ->resolveIpWith(function ($req) {
                return $req->header('X-Real-IP') ?? $req->ip();
            });

        // Request with X-Real-IP header
        $request = StubRequest::create(
            ip: '192.168.1.1',
            headers: ['X-Real-IP' => '10.0.0.1']
        );
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // Allowed because X-Real-IP is whitelisted
    }

    public function test_trust_proxy_with_x_forwarded_for(): void
    {
        $middleware = IpFilterMiddleware::whitelist(['203.0.113.5'])
            ->trustProxy();

        $request = StubRequest::create(
            ip: '127.0.0.1',
            headers: ['X-Forwarded-For' => '203.0.113.5, 192.168.1.1']
        );
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_would_allow_method(): void
    {
        $middleware = new IpFilterMiddleware(
            whitelist: ['192.168.1.1'],
            blacklist: ['10.0.0.0/8'],
            denyByDefault: false,
        );

        $this->assertTrue($middleware->wouldAllow('192.168.1.1'));
        $this->assertFalse($middleware->wouldAllow('10.50.0.1'));
        $this->assertTrue($middleware->wouldAllow('1.2.3.4')); // Not in any list, allow by default
    }

    public function test_get_whitelist_and_blacklist(): void
    {
        $middleware = new IpFilterMiddleware(
            whitelist: ['192.168.1.1'],
            blacklist: ['10.0.0.0/8'],
        );

        $this->assertEquals(['192.168.1.1'], $middleware->getWhitelist()->all());
        $this->assertEquals(['10.0.0.0/8'], $middleware->getBlacklist()->all());
    }

    public function test_block_private_factory(): void
    {
        $middleware = IpFilterMiddleware::blockPrivate();

        $this->assertFalse($middleware->wouldAllow('192.168.1.1'));
        $this->assertFalse($middleware->wouldAllow('10.0.0.1'));
        $this->assertFalse($middleware->wouldAllow('172.16.0.1'));
        $this->assertTrue($middleware->wouldAllow('8.8.8.8'));
    }

    public function test_internal_only_factory(): void
    {
        $middleware = IpFilterMiddleware::internalOnly();

        $this->assertTrue($middleware->wouldAllow('127.0.0.1'));
        $this->assertTrue($middleware->wouldAllow('192.168.1.1'));
        $this->assertTrue($middleware->wouldAllow('10.0.0.1'));
        $this->assertFalse($middleware->wouldAllow('8.8.8.8'));
    }
}
