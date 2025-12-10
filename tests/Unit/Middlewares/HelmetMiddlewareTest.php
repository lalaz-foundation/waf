<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Middlewares;

use Lalaz\Waf\Middlewares\HelmetMiddleware;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

class HelmetMiddlewareTest extends TestCase
{
    public function test_default_security_headers_are_set(): void
    {
        $middleware = new HelmetMiddleware();
        $request = StubRequest::create();
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
        $this->assertEquals('nosniff', $response->getHeader('X-Content-Type-Options'));
        $this->assertEquals('SAMEORIGIN', $response->getHeader('X-Frame-Options'));
        $this->assertEquals('1; mode=block', $response->getHeader('X-XSS-Protection'));
        $this->assertEquals('strict-origin-when-cross-origin', $response->getHeader('Referrer-Policy'));
        $this->assertTrue($response->hasHeader('Content-Security-Policy'));
    }

    public function test_csp_header_is_set_with_custom_value(): void
    {
        $middleware = new HelmetMiddleware(
            contentSecurityPolicy: "default-src 'none'"
        );
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals("default-src 'none'", $response->getHeader('Content-Security-Policy'));
    }

    public function test_hsts_header_is_set_by_default(): void
    {
        $middleware = new HelmetMiddleware();
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $hsts = $response->getHeader('Strict-Transport-Security');
        $this->assertNotNull($hsts);
        $this->assertStringContainsString('max-age=', $hsts);
    }

    public function test_frame_options_deny(): void
    {
        $middleware = new HelmetMiddleware(frameOptions: 'DENY');
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('DENY', $response->getHeader('X-Frame-Options'));
    }

    public function test_strict_factory_method_sets_maximum_security(): void
    {
        $middleware = HelmetMiddleware::strict();
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('DENY', $response->getHeader('X-Frame-Options'));
        $this->assertTrue($response->hasHeader('Content-Security-Policy'));
        $this->assertTrue($response->hasHeader('Strict-Transport-Security'));
        $this->assertTrue($response->hasHeader('Permissions-Policy'));
    }

    public function test_development_factory_method_is_relaxed(): void
    {
        $middleware = HelmetMiddleware::development();
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('nosniff', $response->getHeader('X-Content-Type-Options'));
        $this->assertEquals('SAMEORIGIN', $response->getHeader('X-Frame-Options'));
        // CSP disabled in development
        $this->assertFalse($response->hasHeader('Content-Security-Policy'));
        // HSTS disabled in development
        $this->assertFalse($response->hasHeader('Strict-Transport-Security'));
    }

    public function test_api_factory_method(): void
    {
        $middleware = HelmetMiddleware::api();
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('DENY', $response->getHeader('X-Frame-Options'));
        $this->assertEquals('no-referrer', $response->getHeader('Referrer-Policy'));
        // XSS protection not needed for JSON APIs
        $this->assertFalse($response->hasHeader('X-XSS-Protection'));
    }

    public function test_from_config_factory_method(): void
    {
        $middleware = HelmetMiddleware::fromConfig([
            'frame_options' => 'DENY',
            'referrer_policy' => 'no-referrer',
            'xss_protection' => true,
        ]);

        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('DENY', $response->getHeader('X-Frame-Options'));
        $this->assertEquals('no-referrer', $response->getHeader('Referrer-Policy'));
    }

    public function test_null_csp_disables_header(): void
    {
        $middleware = new HelmetMiddleware(
            contentSecurityPolicy: null
        );
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertFalse($response->hasHeader('Content-Security-Policy'));
    }

    public function test_null_frame_options_disables_header(): void
    {
        $middleware = new HelmetMiddleware(frameOptions: null);
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertFalse($response->hasHeader('X-Frame-Options'));
    }

    public function test_next_middleware_is_always_called(): void
    {
        $middleware = new HelmetMiddleware();
        $request = StubRequest::create();
        $response = new StubResponse();

        $callCount = 0;
        $middleware->handle($request, $response, function () use (&$callCount) {
            $callCount++;
        });

        $this->assertEquals(1, $callCount);
    }

    public function test_cross_origin_headers_are_set(): void
    {
        $middleware = new HelmetMiddleware();
        $request = StubRequest::create();
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('same-origin', $response->getHeader('Cross-Origin-Opener-Policy'));
        $this->assertEquals('same-origin', $response->getHeader('Cross-Origin-Resource-Policy'));
    }
}
