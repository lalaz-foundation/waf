<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Middlewares;

use Lalaz\Waf\Middlewares\RequestSizeLimiterMiddleware;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

class RequestSizeLimiterMiddlewareTest extends TestCase
{
    // ========================================
    // Body Size Tests
    // ========================================

    public function test_allows_request_within_body_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxBodySize: 1024);
        $request = $this->createRequest(body: str_repeat('x', 500));
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_exceeding_body_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxBodySize: 100);
        $request = $this->createRequest(
            body: str_repeat('x', 200),
            headers: ['Content-Length' => '200'],
        );
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    public function test_checks_content_length_header(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxBodySize: 100);
        $request = $this->createRequest(headers: ['Content-Length' => '500']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    // ========================================
    // URL Length Tests
    // ========================================

    public function test_allows_request_within_url_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxUrlLength: 100);
        $request = $this->createRequest(path: '/short/path');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_exceeding_url_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxUrlLength: 50);
        $request = $this->createRequest(path: '/' . str_repeat('a', 100));
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    // ========================================
    // Header Tests
    // ========================================

    public function test_allows_request_within_header_count_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxHeaderCount: 10);
        $request = $this->createRequest(headers: [
            'X-Header-1' => 'value1',
            'X-Header-2' => 'value2',
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_exceeding_header_count_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxHeaderCount: 2);
        $request = $this->createRequest(headers: [
            'X-Header-1' => 'value1',
            'X-Header-2' => 'value2',
            'X-Header-3' => 'value3',
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    public function test_blocks_request_with_oversized_header(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxSingleHeaderSize: 50);
        $request = $this->createRequest(headers: [
            'X-Large-Header' => str_repeat('x', 100),
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    // ========================================
    // Query String Tests
    // ========================================

    public function test_allows_request_within_query_string_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxQueryStringLength: 100);
        $request = $this->createRequest(queryParams: ['foo' => 'bar']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_exceeding_query_string_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxQueryStringLength: 20);
        $request = $this->createRequest(queryParams: [
            'param' => str_repeat('x', 50),
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    public function test_blocks_request_exceeding_query_param_count(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxQueryParams: 3);
        $request = $this->createRequest(queryParams: [
            'a' => '1',
            'b' => '2',
            'c' => '3',
            'd' => '4',
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    // ========================================
    // Body Fields Tests
    // ========================================

    public function test_allows_request_within_body_fields_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxBodyFields: 10);
        $request = $this->createRequest(bodyArray: ['name' => 'John', 'email' => 'john@example.com']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_exceeding_body_fields_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxBodyFields: 3);
        $request = $this->createRequest(bodyArray: [
            'a' => '1',
            'b' => '2',
            'c' => '3',
            'd' => '4',
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    public function test_counts_nested_body_fields(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxBodyFields: 5);
        $request = $this->createRequest(bodyArray: [
            'user' => [
                'name' => 'John',
                'email' => 'john@example.com',
                'address' => [
                    'city' => 'NYC',
                    'zip' => '10001',
                ],
            ],
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        // Should fail: user + name + email + address + city + zip = 6 fields
        $this->assertFalse($called);
    }

    // ========================================
    // JSON Depth Tests
    // ========================================

    public function test_allows_request_within_json_depth_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxJsonDepth: 5);
        $request = $this->createJsonRequest([
            'level1' => [
                'level2' => 'value',
            ],
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    public function test_blocks_request_exceeding_json_depth_limit(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxJsonDepth: 2);
        $request = $this->createJsonRequest([
            'level1' => [
                'level2' => [
                    'level3' => 'value',
                ],
            ],
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(413, $response->getStatusCode());
    }

    // ========================================
    // Custom Handler Tests
    // ========================================

    public function test_custom_exceeded_handler(): void
    {
        $capturedViolation = null;

        $middleware = (new RequestSizeLimiterMiddleware(maxUrlLength: 10))
            ->onExceeded(function ($req, $res, $violation) use (&$capturedViolation) {
                $capturedViolation = $violation;
                $res->json(['blocked' => true], 400);
            });

        $request = $this->createRequest(path: '/' . str_repeat('x', 50));
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertNotNull($capturedViolation);
        $this->assertEquals('url_length', $capturedViolation['type']);
        $this->assertEquals(400, $response->getStatusCode());
    }

    // ========================================
    // Factory Methods Tests
    // ========================================

    public function test_for_api_factory(): void
    {
        $middleware = RequestSizeLimiterMiddleware::forApi();

        $this->assertInstanceOf(RequestSizeLimiterMiddleware::class, $middleware);
        $this->assertEquals(1 * 1024 * 1024, $middleware->getMaxBodySize());
    }

    public function test_for_uploads_factory(): void
    {
        $middleware = RequestSizeLimiterMiddleware::forUploads();

        $this->assertInstanceOf(RequestSizeLimiterMiddleware::class, $middleware);
        $this->assertEquals(100 * 1024 * 1024, $middleware->getMaxBodySize());
    }

    public function test_for_uploads_with_custom_size(): void
    {
        $middleware = RequestSizeLimiterMiddleware::forUploads(50 * 1024 * 1024);

        $this->assertEquals(50 * 1024 * 1024, $middleware->getMaxBodySize());
    }

    public function test_for_forms_factory(): void
    {
        $middleware = RequestSizeLimiterMiddleware::forForms();

        $this->assertInstanceOf(RequestSizeLimiterMiddleware::class, $middleware);
        $this->assertEquals(5 * 1024 * 1024, $middleware->getMaxBodySize());
    }

    public function test_for_graphql_factory(): void
    {
        $middleware = RequestSizeLimiterMiddleware::forGraphQL();

        $this->assertInstanceOf(RequestSizeLimiterMiddleware::class, $middleware);
    }

    public function test_strict_factory(): void
    {
        $middleware = RequestSizeLimiterMiddleware::strict();

        $this->assertInstanceOf(RequestSizeLimiterMiddleware::class, $middleware);
        $this->assertEquals(256 * 1024, $middleware->getMaxBodySize());
    }

    public function test_unlimited_factory(): void
    {
        $middleware = RequestSizeLimiterMiddleware::unlimited();

        $this->assertNull($middleware->getMaxBodySize());
        $this->assertNull($middleware->getMaxUrlLength());
    }

    public function test_from_config(): void
    {
        $middleware = RequestSizeLimiterMiddleware::fromConfig([
            'max_body_size' => 5 * 1024 * 1024,
            'max_url_length' => 1024,
        ]);

        $this->assertEquals(5 * 1024 * 1024, $middleware->getMaxBodySize());
        $this->assertEquals(1024, $middleware->getMaxUrlLength());
    }

    // ========================================
    // Fluent API Tests
    // ========================================

    public function test_fluent_api(): void
    {
        $middleware = RequestSizeLimiterMiddleware::unlimited()
            ->maxBody(1024)
            ->maxUrl(512)
            ->maxHeaders(4096)
            ->maxHeaderCount(50);

        $this->assertEquals(1024, $middleware->getMaxBodySize());
        $this->assertEquals(512, $middleware->getMaxUrlLength());
    }

    // ========================================
    // Helper Methods Tests
    // ========================================

    public function test_would_allow_body_size(): void
    {
        $middleware = new RequestSizeLimiterMiddleware(maxBodySize: 1024);

        $this->assertTrue($middleware->wouldAllowBodySize(500));
        $this->assertTrue($middleware->wouldAllowBodySize(1024));
        $this->assertFalse($middleware->wouldAllowBodySize(2000));
    }

    public function test_null_limit_allows_any_size(): void
    {
        $middleware = RequestSizeLimiterMiddleware::unlimited();

        $this->assertTrue($middleware->wouldAllowBodySize(999999999));
    }

    // ========================================
    // Helper Methods
    // ========================================

    private function createRequest(
        string $path = '/',
        array $queryParams = [],
        string $body = '',
        array $bodyArray = [],
        array $headers = [],
    ): StubRequest {
        $finalBody = !empty($bodyArray) ? $bodyArray : $body;

        return new StubRequest(
            httpMethod: 'POST',
            path: $path,
            headers: $headers,
            ip: '127.0.0.1',
            user: null,
            routeParams: [],
            queryParams: $queryParams,
            body: $finalBody,
        );
    }

    private function createJsonRequest(array $body): StubRequest
    {
        return new StubRequest(
            httpMethod: 'POST',
            path: '/',
            headers: ['Content-Type' => 'application/json'],
            ip: '127.0.0.1',
            user: null,
            routeParams: [],
            queryParams: [],
            body: $body,
        );
    }
}
