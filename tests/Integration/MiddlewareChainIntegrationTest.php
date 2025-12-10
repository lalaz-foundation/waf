<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Integration;

use Lalaz\Waf\Tests\Common\WafIntegrationTestCase;
use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Middlewares\HelmetMiddleware;
use Lalaz\Waf\Middlewares\CorsMiddleware;
use Lalaz\Waf\Middlewares\IpFilterMiddleware;
use Lalaz\Waf\Middlewares\HttpMethodMiddleware;
use Lalaz\Waf\RateLimit\Stores\MemoryStore;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Integration tests for middleware chain execution.
 *
 * These tests verify the complete middleware pipeline including:
 * - Individual middleware behavior
 * - Middleware chaining and order
 * - Request/response modification
 * - Security header injection
 * - Rate limiting integration
 *
 * @package lalaz/waf
 */
final class MiddlewareChainIntegrationTest extends WafIntegrationTestCase
{
    // =========================================================================
    // Rate Limit Middleware Tests
    // =========================================================================

    #[Test]
    public function rate_limit_middleware_allows_requests_within_limit(): void
    {
        $store = $this->createMemoryStore();
        $middleware = (new RateLimitMiddleware(60, 1))->withLimiter($this->createRateLimiter($store));

        $request = $this->createRequest();
        $response = $this->createResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
        $this->assertHasRateLimitHeaders($response);
        $this->assertEquals('60', $response->getHeader('X-RateLimit-Limit'));
    }

    #[Test]
    public function rate_limit_middleware_blocks_requests_exceeding_limit(): void
    {
        $store = $this->createMemoryStore();
        $middleware = (new RateLimitMiddleware(2, 1))->withLimiter($this->createRateLimiter($store));

        $request = $this->createRequest();

        // First two requests should pass
        for ($i = 0; $i < 2; $i++) {
            $response = $this->createResponse();
            $middleware->handle($request, $response, function () {});
        }

        // Third request should be blocked
        $response = $this->createResponse();
        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertResponseRateLimited($response);
        $this->assertTrue($response->hasHeader('Retry-After'));
    }

    #[Test]
    public function rate_limit_middleware_isolates_by_ip(): void
    {
        $store = $this->createMemoryStore();
        $middleware = (new RateLimitMiddleware(1, 1, 'ip'))->withLimiter($this->createRateLimiter($store));

        $request1 = $this->createRequest(ip: '192.168.1.1');
        $request2 = $this->createRequest(ip: '192.168.1.2');

        // Exhaust first IP
        $response = $this->createResponse();
        $middleware->handle($request1, $response, function () {});

        // First IP should be blocked
        $response1 = $this->createResponse();
        $called1 = false;
        $middleware->handle($request1, $response1, function () use (&$called1) {
            $called1 = true;
        });
        $this->assertFalse($called1);

        // Second IP should still work
        $response2 = $this->createResponse();
        $called2 = false;
        $middleware->handle($request2, $response2, function () use (&$called2) {
            $called2 = true;
        });
        $this->assertTrue($called2);
    }

    // =========================================================================
    // Helmet Middleware Tests
    // =========================================================================

    #[Test]
    public function helmet_middleware_adds_security_headers(): void
    {
        $middleware = HelmetMiddleware::strict();
        $request = $this->createRequest();
        $response = $this->createResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertHasSecurityHeaders($response);
        $this->assertEquals('DENY', $response->getHeader('X-Frame-Options'));
        $this->assertEquals('nosniff', $response->getHeader('X-Content-Type-Options'));
        $this->assertEquals('1; mode=block', $response->getHeader('X-XSS-Protection'));
    }

    #[Test]
    public function helmet_middleware_development_mode_relaxes_csp(): void
    {
        $middleware = HelmetMiddleware::development();
        $request = $this->createRequest();
        $response = $this->createResponse();

        $middleware->handle($request, $response, function () {});

        // Should still have basic security headers
        $this->assertTrue($response->hasHeader('X-Frame-Options'));
        $this->assertTrue($response->hasHeader('X-Content-Type-Options'));
    }

    // =========================================================================
    // CORS Middleware Tests
    // =========================================================================

    #[Test]
    public function cors_middleware_handles_preflight_request(): void
    {
        $middleware = CorsMiddleware::allowAll();
        $request = $this->createRequest(
            method: 'OPTIONS',
            headers: [
                'Origin' => 'https://example.com',
                'Access-Control-Request-Method' => 'POST',
            ]
        );
        $response = $this->createResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertHasCorsHeaders($response);
        $this->assertTrue($response->hasHeader('Access-Control-Allow-Methods'));
    }

    #[Test]
    public function cors_middleware_strict_mode_validates_origin(): void
    {
        $middleware = CorsMiddleware::strict(['https://allowed.com']);
        $request = $this->createRequest(
            headers: ['Origin' => 'https://allowed.com']
        );
        $response = $this->createResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('https://allowed.com', $response->getHeader('Access-Control-Allow-Origin'));
    }

    // =========================================================================
    // IP Filter Middleware Tests
    // =========================================================================

    #[Test]
    public function ip_filter_middleware_allows_whitelisted_ip(): void
    {
        $middleware = IpFilterMiddleware::whitelist(['192.168.1.0/24']);
        $request = $this->createRequest(ip: '192.168.1.100');
        $response = $this->createResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    #[Test]
    public function ip_filter_middleware_blocks_non_whitelisted_ip(): void
    {
        $middleware = IpFilterMiddleware::whitelist(['192.168.1.0/24']);
        $request = $this->createRequest(ip: '10.0.0.1');
        $response = $this->createResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertResponseForbidden($response);
    }

    #[Test]
    public function ip_filter_middleware_blocks_blacklisted_ip(): void
    {
        $middleware = IpFilterMiddleware::blacklist(['10.0.0.0/8']);
        $request = $this->createRequest(ip: '10.0.0.1');
        $response = $this->createResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertResponseForbidden($response);
    }

    // =========================================================================
    // HTTP Method Middleware Tests
    // =========================================================================

    #[Test]
    public function http_method_middleware_allows_permitted_methods(): void
    {
        $middleware = HttpMethodMiddleware::restful();
        $request = $this->createRequest(method: 'GET');
        $response = $this->createResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    #[Test]
    public function http_method_middleware_blocks_forbidden_methods(): void
    {
        $middleware = HttpMethodMiddleware::readOnly();
        $request = $this->createRequest(method: 'POST');
        $response = $this->createResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(405, $response->getStatusCode());
    }

    // =========================================================================
    // Sanitization Middleware Tests
    // =========================================================================

    #[Test]
    public function sanitization_middleware_blocks_malicious_input(): void
    {
        $middleware = SanitizationMiddleware::strict();
        $request = $this->createRequest(
            method: 'POST',
            body: ['comment' => '<script>alert("xss")</script>']
        );
        $response = $this->createResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(400, $response->getStatusCode());
    }

    #[Test]
    public function sanitization_middleware_allows_safe_input(): void
    {
        $middleware = SanitizationMiddleware::strict();
        $request = $this->createRequest(
            method: 'POST',
            body: ['comment' => 'This is a safe comment']
        );
        $response = $this->createResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    // =========================================================================
    // Middleware Chain Tests
    // =========================================================================

    #[Test]
    public function middleware_chain_executes_in_order(): void
    {
        $executionOrder = [];

        $middleware1 = new class($executionOrder) {
            private array $order;
            public function __construct(array &$order) { $this->order = &$order; }
            public function handle($req, $res, $next) {
                $this->order[] = 'middleware1';
                $next();
            }
        };

        $middleware2 = new class($executionOrder) {
            private array $order;
            public function __construct(array &$order) { $this->order = &$order; }
            public function handle($req, $res, $next) {
                $this->order[] = 'middleware2';
                $next();
            }
        };

        $request = $this->createRequest();
        $response = $this->createResponse();

        $this->executeMiddlewareChain(
            [$middleware1, $middleware2],
            $request,
            $response,
            function () use (&$executionOrder) {
                $executionOrder[] = 'handler';
            }
        );

        $this->assertEquals(['middleware1', 'middleware2', 'handler'], $executionOrder);
    }

    #[Test]
    public function middleware_chain_stops_on_blocked_request(): void
    {
        $store = $this->createMemoryStore();
        $rateLimitMiddleware = (new RateLimitMiddleware(0, 1))->withLimiter($this->createRateLimiter($store));
        $helmetMiddleware = HelmetMiddleware::strict();

        $request = $this->createRequest();
        $response = $this->createResponse();

        $handlerCalled = false;
        $this->executeMiddlewareChain(
            [$rateLimitMiddleware, $helmetMiddleware],
            $request,
            $response,
            function () use (&$handlerCalled) {
                $handlerCalled = true;
            }
        );

        // Rate limit should block, so handler should not be called
        $this->assertFalse($handlerCalled);
        $this->assertResponseRateLimited($response);
    }

    #[Test]
    public function complete_security_middleware_chain(): void
    {
        $store = $this->createMemoryStore();

        $middlewares = [
            IpFilterMiddleware::blacklist(['10.0.0.0/8']),
            (new RateLimitMiddleware(100, 1))->withLimiter($this->createRateLimiter($store)),
            HttpMethodMiddleware::restful(),
            SanitizationMiddleware::strict(),
            HelmetMiddleware::strict(),
            CorsMiddleware::allowAll(),
        ];

        $request = $this->createRequest(
            method: 'GET',
            ip: '192.168.1.1',
            headers: ['Origin' => 'https://example.com']
        );
        $response = $this->createResponse();

        $handlerCalled = false;
        $this->executeMiddlewareChain(
            $middlewares,
            $request,
            $response,
            function () use (&$handlerCalled) {
                $handlerCalled = true;
            }
        );

        // Request should pass through all middlewares
        $this->assertTrue($handlerCalled);
        $this->assertHasSecurityHeaders($response);
        $this->assertHasRateLimitHeaders($response);
        $this->assertHasCorsHeaders($response);
    }

    // =========================================================================
    // Factory Method Tests
    // =========================================================================

    #[Test]
    #[DataProvider('rateLimitFactoryProvider')]
    public function rate_limit_factory_methods_create_valid_middleware(string $method, array $args): void
    {
        $middleware = RateLimitMiddleware::$method(...$args);
        $this->assertInstanceOf(RateLimitMiddleware::class, $middleware);
    }

    public static function rateLimitFactoryProvider(): array
    {
        return [
            'perMinute' => ['perMinute', [60]],
            'perHour' => ['perHour', [1000]],
            'perDay' => ['perDay', [10000]],
            'forLogin' => ['forLogin', [5, 15]],
            'forApi' => ['forApi', [100]],
        ];
    }

    #[Test]
    #[DataProvider('httpMethodFactoryProvider')]
    public function http_method_factory_methods_create_valid_middleware(string $method): void
    {
        $middleware = HttpMethodMiddleware::$method();
        $this->assertInstanceOf(HttpMethodMiddleware::class, $middleware);
    }

    public static function httpMethodFactoryProvider(): array
    {
        return [
            'readOnly' => ['readOnly'],
            'restful' => ['restful'],
            'safe' => ['safe'],
        ];
    }

    #[Test]
    #[DataProvider('helmetFactoryProvider')]
    public function helmet_factory_methods_create_valid_middleware(string $method): void
    {
        $middleware = HelmetMiddleware::$method();
        $this->assertInstanceOf(HelmetMiddleware::class, $middleware);
    }

    public static function helmetFactoryProvider(): array
    {
        return [
            'strict' => ['strict'],
            'development' => ['development'],
            'api' => ['api'],
        ];
    }
}
