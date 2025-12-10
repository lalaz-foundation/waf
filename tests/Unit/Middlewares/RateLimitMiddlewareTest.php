<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Middlewares;

use Lalaz\Waf\Middlewares\RateLimitMiddleware;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\MemoryStore;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

class RateLimitMiddlewareTest extends TestCase
{
    private RateLimiter $limiter;

    protected function setUp(): void
    {
        $this->limiter = new RateLimiter(new MemoryStore());
    }

    public function test_allows_request_within_limit(): void
    {
        $middleware = (new RateLimitMiddleware(60, 1))->withLimiter($this->limiter);
        $request = StubRequest::create();
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
        $this->assertEquals('60', $response->getHeader('X-RateLimit-Limit'));
    }

    public function test_blocks_request_exceeding_limit(): void
    {
        $middleware = (new RateLimitMiddleware(2, 1))->withLimiter($this->limiter);
        $request = StubRequest::create();
        $response = new StubResponse();

        // First two requests should pass
        for ($i = 0; $i < 2; $i++) {
            $middleware->handle($request, $response, function () {});
        }

        // Third request should be blocked
        $response = new StubResponse();
        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(429, $response->getStatusCode());
    }

    public function test_uses_ip_as_default_key(): void
    {
        $middleware = (new RateLimitMiddleware(1, 1, 'ip'))->withLimiter($this->limiter);

        $request1 = StubRequest::create(ip: '192.168.1.1');
        $request2 = StubRequest::create(ip: '192.168.1.2');
        $response = new StubResponse();

        // First IP should be limited after one request
        $middleware->handle($request1, $response, function () {});

        // Second IP should still be allowed
        $response = new StubResponse();
        $called = false;
        $middleware->handle($request2, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_uses_user_id_as_key(): void
    {
        $middleware = (new RateLimitMiddleware(1, 1, 'user'))->withLimiter($this->limiter);

        $request1 = StubRequest::create(user: (object)['id' => 'user-1']);
        $request2 = StubRequest::create(user: (object)['id' => 'user-2']);
        $response = new StubResponse();

        // First user should be limited after one request
        $middleware->handle($request1, $response, function () {});

        // Second user should still be allowed
        $response = new StubResponse();
        $called = false;
        $middleware->handle($request2, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_uses_route_as_key(): void
    {
        // Route key includes method, path, and IP
        $middleware = (new RateLimitMiddleware(1, 1, 'route'))->withLimiter($this->limiter);

        $request1 = StubRequest::create(method: 'GET', path: '/api/users', ip: '127.0.0.1');
        $request2 = StubRequest::create(method: 'GET', path: '/api/posts', ip: '127.0.0.1');
        $response = new StubResponse();

        // First route should be limited after one request
        $middleware->handle($request1, $response, function () {});

        // Second route should still be allowed (different path)
        $response = new StubResponse();
        $called = false;
        $middleware->handle($request2, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_uses_custom_key_resolver(): void
    {
        $middleware = (new RateLimitMiddleware(
            maxAttempts: 1,
            decayMinutes: 1,
            keyResolver: fn($req) => 'custom-key-' . $req->path()
        ))->withLimiter($this->limiter);

        $request = StubRequest::create(path: '/test');
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        // Second request with same path should be blocked
        $response = new StubResponse();
        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_per_minute_factory_method(): void
    {
        $middleware = RateLimitMiddleware::perMinute(100);
        $this->assertInstanceOf(RateLimitMiddleware::class, $middleware);
    }

    public function test_per_hour_factory_method(): void
    {
        $middleware = RateLimitMiddleware::perHour(1000);
        $this->assertInstanceOf(RateLimitMiddleware::class, $middleware);
    }

    public function test_per_day_factory_method(): void
    {
        $middleware = RateLimitMiddleware::perDay(10000);
        $this->assertInstanceOf(RateLimitMiddleware::class, $middleware);
    }

    public function test_for_login_factory_method(): void
    {
        $middleware = RateLimitMiddleware::forLogin(5, 15);
        $this->assertInstanceOf(RateLimitMiddleware::class, $middleware);
    }

    public function test_for_api_factory_method(): void
    {
        $middleware = RateLimitMiddleware::forApi(60);
        $this->assertInstanceOf(RateLimitMiddleware::class, $middleware);
    }

    public function test_retry_after_header_is_set_on_limit(): void
    {
        $middleware = (new RateLimitMiddleware(1, 1))->withLimiter($this->limiter);
        $request = StubRequest::create();
        $response = new StubResponse();

        // Exhaust limit
        $middleware->handle($request, $response, function () {});

        // Next request should have Retry-After header
        $response = new StubResponse();
        $middleware->handle($request, $response, function () {});

        $this->assertTrue($response->hasHeader('Retry-After'));
    }

    public function test_reset_header_is_set(): void
    {
        $middleware = (new RateLimitMiddleware(60, 1))->withLimiter($this->limiter);
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertTrue($response->hasHeader('X-RateLimit-Reset'));
    }

    public function test_anonymous_user_falls_back_to_ip(): void
    {
        $middleware = (new RateLimitMiddleware(1, 1, 'user'))->withLimiter($this->limiter);
        $request = StubRequest::create(ip: '10.0.0.1', user: null);
        $response = new StubResponse();

        // Should use IP since no user
        $middleware->handle($request, $response, function () {});

        $response = new StubResponse();
        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_from_config_factory_method(): void
    {
        $middleware = RateLimitMiddleware::fromConfig([
            'max_attempts' => 100,
            'decay_minutes' => 5,
            'key' => 'ip',
            'throw_on_limit' => false,
        ]);

        $this->assertInstanceOf(RateLimitMiddleware::class, $middleware);
    }
}
