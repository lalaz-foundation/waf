<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Integration;

use Lalaz\Waf\Tests\Common\WafIntegrationTestCase;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\RateLimitExceededException;
use Lalaz\Waf\RateLimit\Stores\MemoryStore;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Integration tests for complete rate limiting flows.
 *
 * These tests verify the complete rate limiting pipeline including:
 * - Token bucket algorithm behavior
 * - Multiple keys isolation
 * - Time-based token refill
 * - Exception handling
 * - Edge cases and boundary conditions
 *
 * @package lalaz/waf
 */
final class RateLimitFlowIntegrationTest extends WafIntegrationTestCase
{
    // =========================================================================
    // Basic Rate Limiting Flow Tests
    // =========================================================================

    #[Test]
    public function it_allows_requests_within_limit(): void
    {
        $key = 'test:user:1';
        $maxAttempts = 10;

        for ($i = 0; $i < $maxAttempts; $i++) {
            $this->assertIsNotRateLimited($key, $maxAttempts);
            $this->rateLimiter->hit($key, $maxAttempts, self::DEFAULT_DECAY_MINUTES);
        }
    }

    #[Test]
    public function it_blocks_requests_exceeding_limit(): void
    {
        $key = 'test:user:2';
        $maxAttempts = 5;

        // Exhaust all tokens
        $this->exhaustRateLimit($key, $maxAttempts, $maxAttempts);

        // Next request should be blocked
        $this->assertIsRateLimited($key, $maxAttempts);
    }

    #[Test]
    public function it_tracks_remaining_attempts_correctly(): void
    {
        $key = 'test:user:3';
        $maxAttempts = 5;

        // Initial: full bucket
        $this->assertEquals($maxAttempts, $this->getRemainingAttempts($key, $maxAttempts));

        // After 1 hit: 4 remaining
        $this->rateLimiter->hit($key, $maxAttempts, self::DEFAULT_DECAY_MINUTES);
        $this->assertEquals(4, $this->getRemainingAttempts($key, $maxAttempts));

        // After 3 more hits: 1 remaining
        $this->exhaustRateLimit($key, 3, $maxAttempts);
        $this->assertEquals(1, $this->getRemainingAttempts($key, $maxAttempts));

        // After final hit: 0 remaining
        $this->rateLimiter->hit($key, $maxAttempts, self::DEFAULT_DECAY_MINUTES);
        $this->assertEquals(0, $this->getRemainingAttempts($key, $maxAttempts));
    }

    // =========================================================================
    // Key Isolation Tests
    // =========================================================================

    #[Test]
    public function it_isolates_rate_limits_by_key(): void
    {
        $key1 = 'user:1';
        $key2 = 'user:2';
        $key3 = 'user:3';
        $maxAttempts = 3;

        // Exhaust key1
        $this->exhaustRateLimit($key1, $maxAttempts, $maxAttempts);

        // key1 should be limited
        $this->assertIsRateLimited($key1, $maxAttempts);

        // key2 and key3 should NOT be limited
        $this->assertIsNotRateLimited($key2, $maxAttempts);
        $this->assertIsNotRateLimited($key3, $maxAttempts);
    }

    #[Test]
    public function it_supports_different_key_patterns(): void
    {
        $maxAttempts = 2;

        $keys = [
            'ip:192.168.1.1',
            'user:123',
            'route:GET:/api/users',
            'api:key:abc123',
            'login:admin@example.com',
        ];

        foreach ($keys as $key) {
            // Should start fresh for each key
            $this->assertIsNotRateLimited($key, $maxAttempts);

            // Exhaust and verify
            $this->exhaustRateLimit($key, $maxAttempts, $maxAttempts);
            $this->assertIsRateLimited($key, $maxAttempts);
        }
    }

    // =========================================================================
    // Reset and Clear Tests
    // =========================================================================

    #[Test]
    public function it_clears_rate_limit_for_specific_key(): void
    {
        $key = 'test:clear';
        $maxAttempts = 3;

        // Exhaust rate limit
        $this->exhaustRateLimit($key, $maxAttempts, $maxAttempts);
        $this->assertIsRateLimited($key, $maxAttempts);

        // Clear the key
        $this->rateLimiter->clear($key);

        // Should be allowed again
        $this->assertIsNotRateLimited($key, $maxAttempts);
        $this->assertEquals($maxAttempts, $this->getRemainingAttempts($key, $maxAttempts));
    }

    #[Test]
    public function it_provides_reset_timestamp(): void
    {
        $key = 'test:reset';
        $maxAttempts = 5;
        $decayMinutes = 1;

        $this->rateLimiter->hit($key, $maxAttempts, $decayMinutes);

        $resetAt = $this->rateLimiter->resetAt($key, $decayMinutes);
        $now = time();

        // Reset should be in the future (within decay window)
        $this->assertGreaterThan($now, $resetAt);
        $this->assertLessThanOrEqual($now + 61, $resetAt); // +1 for timing variance
    }

    #[Test]
    public function it_provides_available_in_seconds(): void
    {
        $key = 'test:available';
        $maxAttempts = 1;
        $decayMinutes = 1;

        // Exhaust limit
        $this->rateLimiter->hit($key, $maxAttempts, $decayMinutes);

        $availableIn = $this->rateLimiter->availableIn($key, $maxAttempts, $decayMinutes);

        // Should be between 0 and 60 seconds
        $this->assertGreaterThanOrEqual(0, $availableIn);
        $this->assertLessThanOrEqual(60, $availableIn);
    }

    // =========================================================================
    // Hit Return Value Tests
    // =========================================================================

    #[Test]
    public function hit_returns_remaining_tokens(): void
    {
        $key = 'test:hit:return';
        $maxAttempts = 5;

        // Each hit should return decreasing remaining count
        $remaining = [];
        for ($i = 0; $i < $maxAttempts; $i++) {
            $remaining[] = $this->rateLimiter->hit($key, $maxAttempts, self::DEFAULT_DECAY_MINUTES);
        }

        $this->assertEquals([4, 3, 2, 1, 0], $remaining);
    }

    #[Test]
    public function hit_never_returns_below_zero(): void
    {
        $key = 'test:hit:negative';
        $maxAttempts = 2;

        // Hit more than max attempts
        for ($i = 0; $i < 10; $i++) {
            $remaining = $this->rateLimiter->hit($key, $maxAttempts, self::DEFAULT_DECAY_MINUTES);
            $this->assertGreaterThanOrEqual(0, $remaining);
        }
    }

    // =========================================================================
    // Multiple Decay Windows Tests
    // =========================================================================

    #[Test]
    #[DataProvider('decayWindowsProvider')]
    public function it_supports_different_decay_windows(int $decayMinutes, int $expectedMaxSeconds): void
    {
        $key = "test:decay:{$decayMinutes}";
        $maxAttempts = 1;

        $this->rateLimiter->hit($key, $maxAttempts, $decayMinutes);

        $availableIn = $this->rateLimiter->availableIn($key, $maxAttempts, $decayMinutes);

        $this->assertLessThanOrEqual($expectedMaxSeconds, $availableIn);
        $this->assertGreaterThanOrEqual(0, $availableIn);
    }

    public static function decayWindowsProvider(): array
    {
        return [
            '1 minute' => [1, 60],
            '5 minutes' => [5, 300],
            '15 minutes' => [15, 900],
            '60 minutes (1 hour)' => [60, 3600],
        ];
    }

    // =========================================================================
    // Store Integration Tests
    // =========================================================================

    #[Test]
    public function it_works_with_fresh_memory_store(): void
    {
        $store = $this->createMemoryStore();
        $limiter = new RateLimiter($store);

        $key = 'fresh:store:test';
        $maxAttempts = 3;

        // Should work normally
        $this->assertFalse($limiter->tooManyAttempts($key, $maxAttempts, 1));

        for ($i = 0; $i < $maxAttempts; $i++) {
            $limiter->hit($key, $maxAttempts, 1);
        }

        $this->assertTrue($limiter->tooManyAttempts($key, $maxAttempts, 1));
    }

    #[Test]
    public function store_data_persists_across_limiter_instances(): void
    {
        $store = $this->createMemoryStore();
        $key = 'persist:test';
        $maxAttempts = 3;

        // First limiter instance
        $limiter1 = new RateLimiter($store);
        $this->exhaustRateLimit($key, $maxAttempts, $maxAttempts);

        // Second limiter instance with same store
        $limiter2 = new RateLimiter($store);
        $this->assertTrue($limiter2->tooManyAttempts($key, $maxAttempts, 1));
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    #[Test]
    public function it_handles_very_large_max_attempts(): void
    {
        $key = 'large:max';
        $maxAttempts = 1000000;

        $this->assertFalse($this->rateLimiter->tooManyAttempts($key, $maxAttempts, 1));
        $this->assertEquals($maxAttempts, $this->getRemainingAttempts($key, $maxAttempts));
    }

    #[Test]
    public function it_handles_unknown_key(): void
    {
        $key = 'unknown:key:' . uniqid();
        $maxAttempts = 5;

        // Unknown key should not be rate limited
        $this->assertFalse($this->rateLimiter->tooManyAttempts($key, $maxAttempts, 1));

        // Should have full remaining
        $this->assertEquals($maxAttempts, $this->getRemainingAttempts($key, $maxAttempts));
    }

    #[Test]
    public function it_handles_special_characters_in_key(): void
    {
        $keys = [
            'key:with:colons',
            'key/with/slashes',
            'key.with.dots',
            'key-with-dashes',
            'key_with_underscores',
            'key@with@ats',
            'key#with#hashes',
        ];

        $maxAttempts = 2;

        foreach ($keys as $key) {
            $this->assertFalse($this->rateLimiter->tooManyAttempts($key, $maxAttempts, 1));
            $this->exhaustRateLimit($key, $maxAttempts, $maxAttempts);
            $this->assertTrue($this->rateLimiter->tooManyAttempts($key, $maxAttempts, 1));
        }
    }

    // =========================================================================
    // Concurrent Access Simulation Tests
    // =========================================================================

    #[Test]
    public function it_handles_rapid_sequential_requests(): void
    {
        $key = 'rapid:test';
        $maxAttempts = 100;

        // Simulate 100 rapid requests
        for ($i = 0; $i < $maxAttempts; $i++) {
            $this->rateLimiter->hit($key, $maxAttempts, 1);
        }

        // Should be at limit
        $this->assertTrue($this->rateLimiter->tooManyAttempts($key, $maxAttempts, 1));
        $this->assertEquals(0, $this->getRemainingAttempts($key, $maxAttempts));
    }

    // =========================================================================
    // Use Case Tests
    // =========================================================================

    #[Test]
    public function use_case_login_rate_limiting(): void
    {
        $ip = '192.168.1.100';
        $username = 'admin';
        $key = "login:{$ip}:{$username}";
        $maxAttempts = 5;
        $lockoutMinutes = 15;

        // Simulate failed login attempts
        for ($i = 0; $i < $maxAttempts; $i++) {
            $this->assertFalse($this->rateLimiter->tooManyAttempts($key, $maxAttempts, $lockoutMinutes));
            $this->rateLimiter->hit($key, $maxAttempts, $lockoutMinutes);
        }

        // Account should be locked
        $this->assertTrue($this->rateLimiter->tooManyAttempts($key, $maxAttempts, $lockoutMinutes));

        // Get lockout time remaining
        $lockoutRemaining = $this->rateLimiter->availableIn($key, $maxAttempts, $lockoutMinutes);
        $this->assertGreaterThan(0, $lockoutRemaining);

        // Successful login should clear the rate limit
        $this->rateLimiter->clear($key);
        $this->assertFalse($this->rateLimiter->tooManyAttempts($key, $maxAttempts, $lockoutMinutes));
    }

    #[Test]
    public function use_case_api_rate_limiting(): void
    {
        $apiKey = 'api_key_123';
        $key = "api:{$apiKey}";
        $maxAttempts = 100; // 100 requests per minute
        $decayMinutes = 1;

        // Simulate API usage
        for ($i = 0; $i < 50; $i++) {
            $this->assertFalse($this->rateLimiter->tooManyAttempts($key, $maxAttempts, $decayMinutes));
            $this->rateLimiter->hit($key, $maxAttempts, $decayMinutes);
        }

        // Should have 50 remaining
        $this->assertEquals(50, $this->getRemainingAttempts($key, $maxAttempts));

        // Continue to limit
        for ($i = 0; $i < 50; $i++) {
            $this->rateLimiter->hit($key, $maxAttempts, $decayMinutes);
        }

        // Should be rate limited
        $this->assertTrue($this->rateLimiter->tooManyAttempts($key, $maxAttempts, $decayMinutes));
    }
}
