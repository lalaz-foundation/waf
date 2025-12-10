<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Middlewares;

use Lalaz\Waf\Middlewares\HttpMethodMiddleware;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

class HttpMethodMiddlewareTest extends TestCase
{
    // ========================================
    // Basic Allow/Block Tests
    // ========================================

    public function test_allows_configured_method(): void
    {
        $middleware = new HttpMethodMiddleware(['GET', 'POST']);
        $request = $this->createRequest('GET');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_unconfigured_method(): void
    {
        $middleware = new HttpMethodMiddleware(['GET', 'POST']);
        $request = $this->createRequest('DELETE');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(405, $response->getStatusCode());
    }

    public function test_method_comparison_is_case_insensitive(): void
    {
        $middleware = new HttpMethodMiddleware(['get', 'post']);
        $request = $this->createRequest('GET');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    // ========================================
    // OPTIONS Tests (CORS Preflight)
    // ========================================

    public function test_allows_options_by_default(): void
    {
        $middleware = new HttpMethodMiddleware(['GET']);
        $request = $this->createRequest('OPTIONS');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_options_when_disabled(): void
    {
        $middleware = (new HttpMethodMiddleware(['GET']))
            ->allowOptionsRequests(false);

        $request = $this->createRequest('OPTIONS');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(405, $response->getStatusCode());
    }

    // ========================================
    // HEAD Tests
    // ========================================

    public function test_allows_head_when_get_is_allowed(): void
    {
        $middleware = new HttpMethodMiddleware(['GET']);
        $request = $this->createRequest('HEAD');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_head_when_get_not_allowed(): void
    {
        $middleware = new HttpMethodMiddleware(['POST']);
        $request = $this->createRequest('HEAD');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_blocks_head_when_disabled(): void
    {
        $middleware = (new HttpMethodMiddleware(['GET']))
            ->allowHeadRequests(false);

        $request = $this->createRequest('HEAD');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    // ========================================
    // Allow Header Tests
    // ========================================

    public function test_sets_allow_header_on_block(): void
    {
        $middleware = new HttpMethodMiddleware(['GET', 'POST']);
        $request = $this->createRequest('DELETE');
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $allowHeader = $response->getHeader('Allow');
        $this->assertNotNull($allowHeader);
        $this->assertStringContainsString('GET', $allowHeader);
        $this->assertStringContainsString('POST', $allowHeader);
    }

    // ========================================
    // Custom Handler Tests
    // ========================================

    public function test_custom_block_handler(): void
    {
        $capturedMethod = null;

        $middleware = (new HttpMethodMiddleware(['GET']))
            ->onBlock(function ($req, $res, $method, $allowed) use (&$capturedMethod) {
                $capturedMethod = $method;
                $res->json(['custom' => 'blocked'], 400);
            });

        $request = $this->createRequest('DELETE');
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals('DELETE', $capturedMethod);
        $this->assertEquals(400, $response->getStatusCode());
    }

    // ========================================
    // Fluent API Tests
    // ========================================

    public function test_allow_method(): void
    {
        $middleware = (new HttpMethodMiddleware([]))
            ->allow(['GET', 'POST', 'PUT']);

        $this->assertEquals(['GET', 'POST', 'PUT'], $middleware->getAllowedMethods());
    }

    public function test_add_method(): void
    {
        $middleware = (new HttpMethodMiddleware(['GET']))
            ->addMethod('POST')
            ->addMethod('PUT');

        $this->assertContains('GET', $middleware->getAllowedMethods());
        $this->assertContains('POST', $middleware->getAllowedMethods());
        $this->assertContains('PUT', $middleware->getAllowedMethods());
    }

    public function test_add_method_does_not_duplicate(): void
    {
        $middleware = (new HttpMethodMiddleware(['GET']))
            ->addMethod('GET')
            ->addMethod('GET');

        $this->assertCount(1, $middleware->getAllowedMethods());
    }

    public function test_remove_method(): void
    {
        $middleware = (new HttpMethodMiddleware(['GET', 'POST', 'DELETE']))
            ->removeMethod('DELETE');

        $this->assertContains('GET', $middleware->getAllowedMethods());
        $this->assertContains('POST', $middleware->getAllowedMethods());
        $this->assertNotContains('DELETE', $middleware->getAllowedMethods());
    }

    // ========================================
    // Factory Methods Tests
    // ========================================

    public function test_read_only_factory(): void
    {
        $middleware = HttpMethodMiddleware::readOnly();

        $this->assertTrue($middleware->isMethodAllowed('GET'));
        $this->assertTrue($middleware->isMethodAllowed('HEAD')); // Implicit
        $this->assertFalse($middleware->isMethodAllowed('POST'));
        $this->assertFalse($middleware->isMethodAllowed('DELETE'));
    }

    public function test_web_forms_factory(): void
    {
        $middleware = HttpMethodMiddleware::webForms();

        $this->assertTrue($middleware->isMethodAllowed('GET'));
        $this->assertTrue($middleware->isMethodAllowed('POST'));
        $this->assertFalse($middleware->isMethodAllowed('PUT'));
        $this->assertFalse($middleware->isMethodAllowed('DELETE'));
    }

    public function test_restful_factory(): void
    {
        $middleware = HttpMethodMiddleware::restful();

        $this->assertTrue($middleware->isMethodAllowed('GET'));
        $this->assertTrue($middleware->isMethodAllowed('POST'));
        $this->assertTrue($middleware->isMethodAllowed('PUT'));
        $this->assertTrue($middleware->isMethodAllowed('PATCH'));
        $this->assertTrue($middleware->isMethodAllowed('DELETE'));
        $this->assertFalse($middleware->isMethodAllowed('TRACE'));
    }

    public function test_safe_factory(): void
    {
        $middleware = HttpMethodMiddleware::safe();

        $this->assertTrue($middleware->isMethodAllowed('GET'));
        $this->assertTrue($middleware->isMethodAllowed('POST'));
        $this->assertFalse($middleware->isMethodAllowed('TRACE'));
        $this->assertFalse($middleware->isMethodAllowed('CONNECT'));
    }

    public function test_all_factory(): void
    {
        $middleware = HttpMethodMiddleware::all();

        $this->assertTrue($middleware->isMethodAllowed('GET'));
        $this->assertTrue($middleware->isMethodAllowed('TRACE'));
        $this->assertTrue($middleware->isMethodAllowed('CONNECT'));
    }

    public function test_only_factory(): void
    {
        $middleware = HttpMethodMiddleware::only('POST');

        $this->assertTrue($middleware->isMethodAllowed('POST'));
        $this->assertFalse($middleware->isMethodAllowed('GET'));
    }

    public function test_from_config(): void
    {
        $middleware = HttpMethodMiddleware::fromConfig([
            'allowed_methods' => ['GET', 'POST'],
            'allow_options' => false,
            'allow_head' => false,
        ]);

        $this->assertTrue($middleware->isMethodAllowed('GET'));
        $this->assertTrue($middleware->isMethodAllowed('POST'));
        $this->assertFalse($middleware->isMethodAllowed('OPTIONS'));
        $this->assertFalse($middleware->isMethodAllowed('HEAD'));
    }

    // ========================================
    // Utility Methods Tests
    // ========================================

    public function test_is_method_allowed(): void
    {
        $middleware = new HttpMethodMiddleware(['GET', 'POST']);

        $this->assertTrue($middleware->isMethodAllowed('GET'));
        $this->assertTrue($middleware->isMethodAllowed('POST'));
        $this->assertTrue($middleware->isMethodAllowed('OPTIONS')); // Default allowed
        $this->assertTrue($middleware->isMethodAllowed('HEAD')); // Implicit with GET
        $this->assertFalse($middleware->isMethodAllowed('DELETE'));
    }

    public function test_get_allowed_methods(): void
    {
        $middleware = new HttpMethodMiddleware(['GET', 'POST']);

        $allowed = $middleware->getAllowedMethods();

        $this->assertContains('GET', $allowed);
        $this->assertContains('POST', $allowed);
    }

    // ========================================
    // Dangerous Methods Tests
    // ========================================

    public function test_blocks_trace_by_default_with_restful(): void
    {
        $middleware = HttpMethodMiddleware::restful();
        $request = $this->createRequest('TRACE');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_blocks_connect_by_default_with_restful(): void
    {
        $middleware = HttpMethodMiddleware::restful();
        $request = $this->createRequest('CONNECT');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    // ========================================
    // Helper Methods
    // ========================================

    private function createRequest(string $method): StubRequest
    {
        return new StubRequest(
            httpMethod: $method,
            path: '/',
            headers: [],
            ip: '127.0.0.1',
        );
    }
}
