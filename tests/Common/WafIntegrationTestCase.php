<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Common;

use Lalaz\Waf\Detection\ThreatDetector;
use Lalaz\Waf\Detection\ThreatType;
use Lalaz\Waf\Geo\GeoLocation;
use Lalaz\Waf\Geo\Providers\ArrayGeoProvider;
use Lalaz\Waf\IpFilter\IpList;
use Lalaz\Waf\IpFilter\IpMatcher;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\MemoryStore;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

/**
 * Base test case for WAF package integration tests.
 *
 * Provides comprehensive utilities for testing complete WAF flows
 * including middleware chains, threat detection pipelines,
 * and rate limiting integration.
 *
 * @package lalaz/waf
 */
abstract class WafIntegrationTestCase extends TestCase
{
    /**
     * Default rate limit for testing.
     */
    protected const DEFAULT_RATE_LIMIT = 60;

    /**
     * Default decay window in minutes.
     */
    protected const DEFAULT_DECAY_MINUTES = 1;

    /**
     * Test client IP.
     */
    protected const TEST_CLIENT_IP = '203.0.113.1';

    /**
     * Test user agent.
     */
    protected const TEST_USER_AGENT = 'Mozilla/5.0 (Test) WAF/1.0';

    protected RateLimiter $rateLimiter;
    protected MemoryStore $memoryStore;
    protected ThreatDetector $threatDetector;

    /**
     * Setup the test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->memoryStore = new MemoryStore();
        $this->memoryStore->clearAll();
        $this->rateLimiter = new RateLimiter($this->memoryStore);
        $this->threatDetector = ThreatDetector::all();
    }

    /**
     * Tear down the test environment.
     */
    protected function tearDown(): void
    {
        if (isset($this->memoryStore)) {
            $this->memoryStore->clearAll();
        }

        parent::tearDown();
    }

    // =========================================================================
    // Factory Methods
    // =========================================================================

    /**
     * Create a stub request for testing.
     */
    protected function createRequest(
        string $method = 'GET',
        string $path = '/',
        array $headers = [],
        string $ip = self::TEST_CLIENT_IP,
        ?object $user = null,
        mixed $body = [],
        array $queryParams = [],
    ): StubRequest {
        $defaultHeaders = [
            'User-Agent' => self::TEST_USER_AGENT,
        ];

        return new StubRequest(
            httpMethod: $method,
            path: $path,
            headers: array_merge($defaultHeaders, $headers),
            ip: $ip,
            user: $user,
            body: $body,
            queryParams: $queryParams,
        );
    }

    /**
     * Create a stub response for testing.
     */
    protected function createResponse(): StubResponse
    {
        return new StubResponse();
    }

    /**
     * Create a test user object.
     */
    protected function createTestUser(int|string $id = 1, array $attributes = []): object
    {
        return (object) array_merge(['id' => $id], $attributes);
    }

    /**
     * Create an array geo provider with test data.
     */
    protected function createGeoProvider(array $data = []): ArrayGeoProvider
    {
        $defaultData = [
            '8.8.8.8' => GeoLocation::fromArray([
                'country_code' => 'US',
                'country_name' => 'United States',
                'region_name' => 'California',
                'city' => 'Mountain View',
            ]),
            '1.1.1.1' => GeoLocation::fromArray([
                'country_code' => 'AU',
                'country_name' => 'Australia',
            ]),
            '203.0.113.1' => GeoLocation::fromArray([
                'country_code' => 'US',
                'country_name' => 'United States',
            ]),
            '203.0.113.100' => GeoLocation::fromArray([
                'country_code' => 'CN',
                'country_name' => 'China',
            ]),
            '203.0.113.200' => GeoLocation::fromArray([
                'country_code' => 'RU',
                'country_name' => 'Russia',
            ]),
        ];

        return new ArrayGeoProvider(array_merge($defaultData, $data));
    }

    /**
     * Create a fresh memory store.
     */
    protected function createMemoryStore(): MemoryStore
    {
        $store = new MemoryStore();
        $store->clearAll();
        return $store;
    }

    /**
     * Create a fresh rate limiter.
     */
    protected function createRateLimiter(?MemoryStore $store = null): RateLimiter
    {
        return new RateLimiter($store ?? $this->createMemoryStore());
    }

    /**
     * Create an IP list with optional initial IPs.
     *
     * @param string $name List name.
     * @param array $patterns Initial IP patterns.
     */
    protected function createIpList(string $name = 'test', array $patterns = []): IpList
    {
        return new IpList($name, $patterns);
    }

    // =========================================================================
    // Threat Detection Helpers
    // =========================================================================

    /**
     * Scan input for threats and return results.
     */
    protected function scanForThreats(string $input): array
    {
        return $this->threatDetector->scan($input);
    }

    /**
     * Check if input contains any threat.
     */
    protected function hasThreat(string $input): bool
    {
        return $this->threatDetector->hasThreat($input);
    }

    /**
     * Check if input contains a specific threat type.
     */
    protected function hasThreatType(string $input, ThreatType $type): bool
    {
        $threats = $this->scanForThreats($input);

        foreach ($threats as $threat) {
            if ($threat->type === $type) {
                return true;
            }
        }

        return false;
    }

    // =========================================================================
    // Rate Limiting Helpers
    // =========================================================================

    /**
     * Simulate multiple requests to exhaust rate limit.
     */
    protected function exhaustRateLimit(
        string $key,
        int $attempts,
        int $maxAttempts = self::DEFAULT_RATE_LIMIT,
        int $decayMinutes = self::DEFAULT_DECAY_MINUTES
    ): void {
        for ($i = 0; $i < $attempts; $i++) {
            $this->rateLimiter->hit($key, $maxAttempts, $decayMinutes);
        }
    }

    /**
     * Check if a key is rate limited.
     */
    protected function isRateLimited(
        string $key,
        int $maxAttempts = self::DEFAULT_RATE_LIMIT,
        int $decayMinutes = self::DEFAULT_DECAY_MINUTES
    ): bool {
        return $this->rateLimiter->tooManyAttempts($key, $maxAttempts, $decayMinutes);
    }

    /**
     * Get remaining attempts for a key.
     */
    protected function getRemainingAttempts(
        string $key,
        int $maxAttempts = self::DEFAULT_RATE_LIMIT,
        int $decayMinutes = self::DEFAULT_DECAY_MINUTES
    ): int {
        return $this->rateLimiter->remaining($key, $maxAttempts, $decayMinutes);
    }

    // =========================================================================
    // Middleware Simulation Helpers
    // =========================================================================

    /**
     * Simulate a middleware chain execution.
     *
     * @param array $middlewares Array of middleware instances
     * @param StubRequest $request
     * @param StubResponse $response
     * @param callable $finalHandler Final handler to call if all middlewares pass
     * @return StubResponse
     */
    protected function executeMiddlewareChain(
        array $middlewares,
        StubRequest $request,
        StubResponse $response,
        callable $finalHandler
    ): StubResponse {
        $index = 0;
        $count = count($middlewares);

        $next = function () use (&$index, &$next, $middlewares, $count, $request, $response, $finalHandler) {
            if ($index >= $count) {
                $finalHandler($request, $response);
                return;
            }

            $middleware = $middlewares[$index++];
            $middleware->handle($request, $response, $next);
        };

        $next();

        return $response;
    }

    // =========================================================================
    // Assertions
    // =========================================================================

    /**
     * Assert that a payload is detected as XSS.
     */
    protected function assertXssDetected(string $payload, string $message = ''): void
    {
        $this->assertTrue(
            $this->hasThreatType($payload, ThreatType::XSS),
            $message ?: "Payload should be detected as XSS: {$payload}"
        );
    }

    /**
     * Assert that a payload is detected as SQL Injection.
     */
    protected function assertSqlInjectionDetected(string $payload, string $message = ''): void
    {
        $this->assertTrue(
            $this->hasThreatType($payload, ThreatType::SQL_INJECTION),
            $message ?: "Payload should be detected as SQL Injection: {$payload}"
        );
    }

    /**
     * Assert that a payload is detected as Path Traversal.
     */
    protected function assertPathTraversalDetected(string $payload, string $message = ''): void
    {
        $this->assertTrue(
            $this->hasThreatType($payload, ThreatType::PATH_TRAVERSAL),
            $message ?: "Payload should be detected as Path Traversal: {$payload}"
        );
    }

    /**
     * Assert that a payload is safe (no threats detected).
     */
    protected function assertPayloadIsSafe(string $payload, string $message = ''): void
    {
        $this->assertFalse(
            $this->hasThreat($payload),
            $message ?: "Payload should be safe: {$payload}"
        );
    }

    /**
     * Assert that a key is rate limited.
     */
    protected function assertIsRateLimited(
        string $key,
        int $maxAttempts = self::DEFAULT_RATE_LIMIT,
        int $decayMinutes = self::DEFAULT_DECAY_MINUTES,
        string $message = ''
    ): void {
        $this->assertTrue(
            $this->isRateLimited($key, $maxAttempts, $decayMinutes),
            $message ?: "Key {$key} should be rate limited"
        );
    }

    /**
     * Assert that a key is NOT rate limited.
     */
    protected function assertIsNotRateLimited(
        string $key,
        int $maxAttempts = self::DEFAULT_RATE_LIMIT,
        int $decayMinutes = self::DEFAULT_DECAY_MINUTES,
        string $message = ''
    ): void {
        $this->assertFalse(
            $this->isRateLimited($key, $maxAttempts, $decayMinutes),
            $message ?: "Key {$key} should NOT be rate limited"
        );
    }

    /**
     * Assert response is successful (2xx status code).
     */
    protected function assertResponseSuccess(StubResponse $response, string $message = ''): void
    {
        $status = $response->getStatusCode();
        $this->assertTrue(
            $status >= 200 && $status < 300,
            $message ?: "Response should be successful, got {$status}"
        );
    }

    /**
     * Assert response is a rate limit response (429).
     */
    protected function assertResponseRateLimited(StubResponse $response, string $message = ''): void
    {
        $this->assertEquals(
            429,
            $response->getStatusCode(),
            $message ?: 'Response should be rate limited (429)'
        );
    }

    /**
     * Assert response is forbidden (403).
     */
    protected function assertResponseForbidden(StubResponse $response, string $message = ''): void
    {
        $this->assertEquals(
            403,
            $response->getStatusCode(),
            $message ?: 'Response should be forbidden (403)'
        );
    }

    /**
     * Assert response has security headers.
     */
    protected function assertHasSecurityHeaders(StubResponse $response, string $message = ''): void
    {
        $securityHeaders = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
        ];

        foreach ($securityHeaders as $header) {
            $this->assertTrue(
                $response->hasHeader($header),
                $message ?: "Response should have security header: {$header}"
            );
        }
    }

    /**
     * Assert response has CORS headers.
     */
    protected function assertHasCorsHeaders(StubResponse $response, string $message = ''): void
    {
        $this->assertTrue(
            $response->hasHeader('Access-Control-Allow-Origin'),
            $message ?: 'Response should have CORS header'
        );
    }

    /**
     * Assert response has rate limit headers.
     */
    protected function assertHasRateLimitHeaders(StubResponse $response, string $message = ''): void
    {
        $rateLimitHeaders = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
        ];

        foreach ($rateLimitHeaders as $header) {
            $this->assertTrue(
                $response->hasHeader($header),
                $message ?: "Response should have rate limit header: {$header}"
            );
        }
    }
}
