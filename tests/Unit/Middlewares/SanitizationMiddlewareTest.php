<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Middlewares;

use Lalaz\Waf\Detection\ThreatType;
use Lalaz\Waf\Middlewares\SanitizationMiddleware;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

class SanitizationMiddlewareTest extends TestCase
{
    // ========================================
    // Basic Detection Tests
    // ========================================

    public function test_blocks_xss_in_body(): void
    {
        $middleware = new SanitizationMiddleware();
        $request = $this->createRequest(body: ['comment' => '<script>alert(1)</script>']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(400, $response->getStatusCode());
    }

    public function test_blocks_sql_injection_in_query(): void
    {
        $middleware = new SanitizationMiddleware();
        $request = $this->createRequest(queryParams: ['id' => "1 OR 1=1--"]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(400, $response->getStatusCode());
    }

    public function test_blocks_path_traversal_in_path(): void
    {
        $middleware = new SanitizationMiddleware();
        $request = $this->createRequest(path: '/files/../../../etc/passwd');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
        $this->assertEquals(400, $response->getStatusCode());
    }

    public function test_allows_safe_requests(): void
    {
        $middleware = new SanitizationMiddleware();
        $request = $this->createRequest(
            body: ['name' => 'John Doe', 'email' => 'john@example.com'],
            queryParams: ['page' => '1', 'limit' => '10'],
        );
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called);
    }

    // ========================================
    // Log Only Mode Tests
    // ========================================

    public function test_log_only_mode_allows_threats(): void
    {
        $middleware = SanitizationMiddleware::logOnly();
        $request = $this->createRequest(body: ['comment' => '<script>alert(1)</script>']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // Should not block in log-only mode
    }

    public function test_log_only_mode_calls_threat_handler(): void
    {
        $detectedThreats = null;

        $middleware = SanitizationMiddleware::logOnly()
            ->onThreat(function ($req, $threats) use (&$detectedThreats) {
                $detectedThreats = $threats;
            });

        $request = $this->createRequest(body: ['comment' => '<script>alert(1)</script>']);
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertNotNull($detectedThreats);
        $this->assertGreaterThanOrEqual(1, count($detectedThreats));
    }

    // ========================================
    // On Threat Handler Tests
    // ========================================

    public function test_on_threat_handler_is_called(): void
    {
        $handlerCalled = false;

        $middleware = (new SanitizationMiddleware())
            ->onThreat(function ($req, $threats) use (&$handlerCalled) {
                $handlerCalled = true;
            });

        $request = $this->createRequest(body: ['xss' => '<script>alert(1)</script>']);
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertTrue($handlerCalled);
    }

    public function test_on_block_handler_customizes_response(): void
    {
        $middleware = (new SanitizationMiddleware())
            ->onBlock(function ($req, $res, $threats) {
                $res->json(['blocked' => true, 'count' => count($threats)], 403);
            });

        $request = $this->createRequest(body: ['xss' => '<script>alert(1)</script>']);
        $response = new StubResponse();

        $middleware->handle($request, $response, function () {});

        $this->assertEquals(403, $response->getStatusCode());
        $body = $response->getJsonBody();
        $this->assertTrue($body['blocked']);
    }

    // ========================================
    // Scan Configuration Tests
    // ========================================

    public function test_disable_path_scanning(): void
    {
        $middleware = (new SanitizationMiddleware())
            ->scan(path: false, query: true, body: true);

        $request = $this->createRequest(path: '/files/../../../etc/passwd');
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // Path scanning disabled, should pass
    }

    public function test_disable_query_scanning(): void
    {
        $middleware = (new SanitizationMiddleware())
            ->scan(path: true, query: false, body: true);

        $request = $this->createRequest(queryParams: ['id' => "1 OR 1=1--"]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // Query scanning disabled, should pass
    }

    public function test_disable_body_scanning(): void
    {
        $middleware = (new SanitizationMiddleware())
            ->scan(path: true, query: true, body: false);

        $request = $this->createRequest(body: ['xss' => '<script>alert(1)</script>']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // Body scanning disabled, should pass
    }

    // ========================================
    // Field Exclusion Tests
    // ========================================

    public function test_exclude_fields(): void
    {
        $middleware = (new SanitizationMiddleware())
            ->excludeFields(['html_content']);

        $request = $this->createRequest(body: [
            'html_content' => '<script>alert(1)</script>',
            'comment' => 'Hello World',
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // Excluded field, should pass
    }

    public function test_html_fields_skip_xss(): void
    {
        $middleware = (new SanitizationMiddleware())
            ->htmlFields(['content']);

        $request = $this->createRequest(body: [
            'content' => '<b>Bold text</b><script>evil()</script>',
        ]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // HTML field, XSS skipped
    }

    // ========================================
    // Factory Methods Tests
    // ========================================

    public function test_strict_factory(): void
    {
        $middleware = SanitizationMiddleware::strict();

        $this->assertInstanceOf(SanitizationMiddleware::class, $middleware);
    }

    public function test_basic_factory(): void
    {
        $middleware = SanitizationMiddleware::basic();

        $this->assertInstanceOf(SanitizationMiddleware::class, $middleware);
    }

    public function test_for_api_factory(): void
    {
        $middleware = SanitizationMiddleware::forApi();

        // API mode still checks SQL injection and path traversal
        $request = $this->createRequest(body: ['id' => "1 OR 1=1--"]);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called); // SQL injection should be blocked
    }

    public function test_for_forms_factory(): void
    {
        $middleware = SanitizationMiddleware::forForms();

        // Forms mode checks XSS
        $request = $this->createRequest(body: ['comment' => '<script>alert(1)</script>']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertFalse($called);
    }

    public function test_from_config(): void
    {
        $middleware = SanitizationMiddleware::fromConfig([
            'detect_xss' => true,
            'detect_sql_injection' => true,
            'detect_path_traversal' => false,
            'log_only' => false,
        ]);

        $this->assertInstanceOf(SanitizationMiddleware::class, $middleware);
    }

    // ========================================
    // Block Types Tests
    // ========================================

    public function test_block_only_specific_types(): void
    {
        $middleware = (new SanitizationMiddleware())
            ->blockOnly([ThreatType::SQL_INJECTION]);

        // XSS should be detected but not blocked
        $request = $this->createRequest(body: ['xss' => '<script>alert(1)</script>']);
        $response = new StubResponse();

        $called = false;
        $middleware->handle($request, $response, function () use (&$called) {
            $called = true;
        });

        $this->assertTrue($called); // XSS not in blockOnly list
    }

    // ========================================
    // Nested Data Tests
    // ========================================

    public function test_detects_threats_in_nested_data(): void
    {
        $middleware = new SanitizationMiddleware();
        $request = $this->createRequest(body: [
            'user' => [
                'profile' => [
                    'bio' => '<script>alert(1)</script>',
                ],
            ],
        ]);
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

    private function createRequest(
        string $path = '/',
        array $queryParams = [],
        array $body = [],
        array $headers = [],
    ): StubRequest {
        return new StubRequest(
            httpMethod: 'POST',
            path: $path,
            headers: $headers,
            ip: '127.0.0.1',
            user: null,
            routeParams: [],
            queryParams: $queryParams,
            body: $body,
        );
    }
}
