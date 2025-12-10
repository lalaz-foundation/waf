<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Middlewares;

use Lalaz\Waf\Middlewares\CorsMiddleware;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

class CorsMiddlewareTest extends TestCase
{
    public function test_allows_request_without_origin_header(): void
    {
        $middleware = new CorsMiddleware();
        $request = StubRequest::create();
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_adds_cors_headers_for_allowed_origin(): void
    {
        $middleware = new CorsMiddleware(allowedOrigins: ['https://example.com']);
        $request = StubRequest::create(headers: ['Origin' => 'https://example.com']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
        $this->assertEquals('https://example.com', $response->getHeader('Access-Control-Allow-Origin'));
    }

    public function test_rejects_disallowed_origin(): void
    {
        $middleware = new CorsMiddleware(allowedOrigins: ['https://allowed.com']);
        $request = StubRequest::create(headers: ['Origin' => 'https://evil.com']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_handles_preflight_request(): void
    {
        $middleware = new CorsMiddleware();
        $request = StubRequest::create(
            method: 'OPTIONS',
            headers: [
                'Origin' => 'https://example.com',
                'Access-Control-Request-Method' => 'POST',
            ]
        );
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called); // Preflight should not call next
        $this->assertEquals(204, $response->getStatusCode());
    }

    public function test_allow_all_factory_method(): void
    {
        $middleware = CorsMiddleware::allowAll();
        $request = StubRequest::create(headers: ['Origin' => 'https://any-origin.com']);
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('*', $response->getHeader('Access-Control-Allow-Origin'));
    }

    public function test_strict_factory_method(): void
    {
        $middleware = CorsMiddleware::strict(['https://myapp.com'], true);
        $request = StubRequest::create(headers: ['Origin' => 'https://myapp.com']);
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('https://myapp.com', $response->getHeader('Access-Control-Allow-Origin'));
        $this->assertEquals('true', $response->getHeader('Access-Control-Allow-Credentials'));
    }

    public function test_from_config_factory_method(): void
    {
        $middleware = CorsMiddleware::fromConfig([
            'allowed_origins' => ['https://config.com'],
            'allowed_methods' => ['GET', 'POST'],
            'max_age' => 3600,
        ]);

        $this->assertInstanceOf(CorsMiddleware::class, $middleware);
    }

    public function test_wildcard_origin_matching(): void
    {
        $middleware = new CorsMiddleware(allowedOrigins: ['*.example.com']);
        $request = StubRequest::create(headers: ['Origin' => 'https://api.example.com']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }
}
