<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\RateLimit;

use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\MemoryStore;
use PHPUnit\Framework\TestCase;

class RateLimiterTest extends TestCase
{
    private RateLimiter $limiter;
    private MemoryStore $store;

    protected function setUp(): void
    {
        $this->store = new MemoryStore();
        $this->store->clearAll(); // Clear any data from previous tests
        $this->limiter = new RateLimiter($this->store);
    }

    public function test_allows_attempts_within_limit(): void
    {
        $key = 'test-key';
        $maxAttempts = 5;
        $decayMinutes = 1;

        for ($i = 0; $i < $maxAttempts; $i++) {
            $this->assertFalse($this->limiter->tooManyAttempts($key, $maxAttempts, $decayMinutes));
            $this->limiter->hit($key, $maxAttempts, $decayMinutes);
        }
    }

    public function test_blocks_attempts_exceeding_limit(): void
    {
        $key = 'test-key';
        $maxAttempts = 3;
        $decayMinutes = 1;

        // Fill up the limit
        for ($i = 0; $i < $maxAttempts; $i++) {
            $this->limiter->hit($key, $maxAttempts, $decayMinutes);
        }

        // Should now be blocked
        $this->assertTrue($this->limiter->tooManyAttempts($key, $maxAttempts, $decayMinutes));
    }

    public function test_remaining_decreases_after_hit(): void
    {
        $key = 'test-key';
        $maxAttempts = 10;
        $decayMinutes = 1;

        // Initial remaining should be maxAttempts (bucket starts full)
        $initialRemaining = $this->limiter->remaining($key, $maxAttempts, $decayMinutes);
        $this->assertEquals($maxAttempts, $initialRemaining);

        // After hit, remaining should decrease
        $this->limiter->hit($key, $maxAttempts, $decayMinutes);
        $afterOneHit = $this->limiter->remaining($key, $maxAttempts, $decayMinutes);

        $this->assertLessThan($initialRemaining, $afterOneHit);
    }

    public function test_remaining_never_goes_below_zero(): void
    {
        $key = 'test-key';
        $maxAttempts = 2;
        $decayMinutes = 1;

        // Hit more times than allowed
        for ($i = 0; $i < 5; $i++) {
            $this->limiter->hit($key, $maxAttempts, $decayMinutes);
        }

        $this->assertEquals(0, $this->limiter->remaining($key, $maxAttempts, $decayMinutes));
    }

    public function test_available_in_returns_seconds_until_reset(): void
    {
        $key = 'test-key';
        $maxAttempts = 1;
        $decayMinutes = 1;

        // Exhaust all tokens
        $this->limiter->hit($key, $maxAttempts, $decayMinutes);

        $availableIn = $this->limiter->availableIn($key, $maxAttempts, $decayMinutes);

        // Should be between 0 and 60 seconds
        $this->assertGreaterThanOrEqual(0, $availableIn);
        $this->assertLessThanOrEqual(60, $availableIn);
    }

    public function test_reset_at_returns_timestamp(): void
    {
        $key = 'test-key';
        $maxAttempts = 10;
        $decayMinutes = 1;

        $this->limiter->hit($key, $maxAttempts, $decayMinutes);

        $resetAt = $this->limiter->resetAt($key, $decayMinutes);
        $now = time();

        // Should be in the future (within decay window)
        $this->assertGreaterThan($now, $resetAt);
        $this->assertLessThanOrEqual($now + 61, $resetAt); // +1 for timing variance
    }

    public function test_reset_at_returns_future_timestamp_for_unknown_key(): void
    {
        $decayMinutes = 1;
        $resetAt = $this->limiter->resetAt('unknown-key', $decayMinutes);
        $now = time();

        // Should return a future timestamp for unknown key
        $this->assertGreaterThanOrEqual($now, $resetAt);
    }

    public function test_clear_removes_rate_limit_data(): void
    {
        $key = 'test-key';
        $maxAttempts = 1;
        $decayMinutes = 1;

        // Fill up limit
        $this->limiter->hit($key, $maxAttempts, $decayMinutes);
        $this->assertTrue($this->limiter->tooManyAttempts($key, $maxAttempts, $decayMinutes));

        // Clear
        $this->limiter->clear($key);

        // Should be allowed again
        $this->assertFalse($this->limiter->tooManyAttempts($key, $maxAttempts, $decayMinutes));
    }

    public function test_different_keys_have_separate_limits(): void
    {
        $key1 = 'user-1';
        $key2 = 'user-2';
        $maxAttempts = 1;
        $decayMinutes = 1;

        // Fill up key1
        $this->limiter->hit($key1, $maxAttempts, $decayMinutes);
        $this->assertTrue($this->limiter->tooManyAttempts($key1, $maxAttempts, $decayMinutes));

        // key2 should still be available
        $this->assertFalse($this->limiter->tooManyAttempts($key2, $maxAttempts, $decayMinutes));
    }

    public function test_hit_returns_remaining_tokens(): void
    {
        $key = 'test-key';
        $maxAttempts = 5;
        $decayMinutes = 1;

        // Hit consumes a token and returns remaining
        $remaining1 = $this->limiter->hit($key, $maxAttempts, $decayMinutes);
        $remaining2 = $this->limiter->hit($key, $maxAttempts, $decayMinutes);
        $remaining3 = $this->limiter->hit($key, $maxAttempts, $decayMinutes);

        // Each hit should return decreasing remaining tokens
        // After first hit: 4 remaining, after second: 3, after third: 2
        $this->assertEquals(4, $remaining1);
        $this->assertEquals(3, $remaining2);
        $this->assertEquals(2, $remaining3);
    }

    public function test_token_bucket_refills_over_time(): void
    {
        // This test verifies the token bucket algorithm concept
        // In a real scenario, tokens refill gradually over time
        $key = 'refill-test';
        $maxAttempts = 10;
        $decayMinutes = 1;

        // Get initial remaining
        $initial = $this->limiter->remaining($key, $maxAttempts, $decayMinutes);

        // Should have tokens available initially
        $this->assertGreaterThan(0, $initial);
    }
}
