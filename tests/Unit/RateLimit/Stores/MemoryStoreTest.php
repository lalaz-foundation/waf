<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\RateLimit\Stores;

use Lalaz\Waf\RateLimit\Stores\MemoryStore;
use PHPUnit\Framework\TestCase;

class MemoryStoreTest extends TestCase
{
    private MemoryStore $store;

    protected function setUp(): void
    {
        $this->store = new MemoryStore();
        $this->store->clearAll(); // Clear any data from previous tests
    }

    public function test_get_bucket_returns_null_for_new_key(): void
    {
        $this->assertNull($this->store->getBucket('non-existent-key'));
    }

    public function test_save_and_get_bucket(): void
    {
        $key = 'test-key';
        $bucket = [
            'attempts' => 5,
            'reset_at' => time() + 60,
        ];

        $this->store->saveBucket($key, $bucket, 60);

        $retrieved = $this->store->getBucket($key);

        $this->assertEquals($bucket['attempts'], $retrieved['attempts']);
        $this->assertEquals($bucket['reset_at'], $retrieved['reset_at']);
    }

    public function test_clear_removes_bucket(): void
    {
        $key = 'test-key';
        $bucket = [
            'attempts' => 3,
            'reset_at' => time() + 60,
        ];

        $this->store->saveBucket($key, $bucket, 60);
        $this->assertNotNull($this->store->getBucket($key));

        $this->store->clear($key);
        $this->assertNull($this->store->getBucket($key));
    }

    public function test_multiple_keys_are_independent(): void
    {
        $bucket1 = ['attempts' => 1, 'reset_at' => time() + 60];
        $bucket2 = ['attempts' => 2, 'reset_at' => time() + 120];

        $this->store->saveBucket('key1', $bucket1, 60);
        $this->store->saveBucket('key2', $bucket2, 120);

        $retrieved1 = $this->store->getBucket('key1');
        $retrieved2 = $this->store->getBucket('key2');

        $this->assertEquals(1, $retrieved1['attempts']);
        $this->assertEquals(2, $retrieved2['attempts']);
    }

    public function test_update_existing_bucket(): void
    {
        $key = 'test-key';

        $this->store->saveBucket($key, ['attempts' => 1, 'reset_at' => time() + 60], 60);
        $this->store->saveBucket($key, ['attempts' => 5, 'reset_at' => time() + 60], 60);

        $retrieved = $this->store->getBucket($key);

        $this->assertEquals(5, $retrieved['attempts']);
    }
}
