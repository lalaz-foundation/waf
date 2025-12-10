<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\RateLimit\Stores;

use Lalaz\Waf\RateLimit\Stores\APCuStore;
use PHPUnit\Framework\TestCase;

/**
 * @requires extension apcu
 */
class APCuStoreTest extends TestCase
{
    private ?APCuStore $store = null;

    protected function setUp(): void
    {
        if (!APCuStore::isAvailable()) {
            $this->markTestSkipped('APCu extension is not available');
        }

        $this->store = new APCuStore('test:rl:');
        $this->store->clearAll();
    }

    protected function tearDown(): void
    {
        if ($this->store !== null) {
            $this->store->clearAll();
        }
    }

    public function test_get_bucket_returns_null_for_new_key(): void
    {
        $this->assertNull($this->store->getBucket('non-existent-key'));
    }

    public function test_save_and_get_bucket(): void
    {
        $key = 'test-key';
        $bucket = [
            'tokens' => 5.0,
            'last_refill' => microtime(true),
        ];

        $this->store->saveBucket($key, $bucket, 60);

        $retrieved = $this->store->getBucket($key);

        $this->assertNotNull($retrieved);
        $this->assertEquals($bucket['tokens'], $retrieved['tokens']);
    }

    public function test_clear_removes_bucket(): void
    {
        $key = 'test-key';
        $bucket = [
            'tokens' => 3.0,
            'last_refill' => microtime(true),
        ];

        $this->store->saveBucket($key, $bucket, 60);
        $this->assertNotNull($this->store->getBucket($key));

        $this->store->clear($key);
        $this->assertNull($this->store->getBucket($key));
    }

    public function test_multiple_keys_are_independent(): void
    {
        $bucket1 = ['tokens' => 1.0, 'last_refill' => microtime(true)];
        $bucket2 = ['tokens' => 2.0, 'last_refill' => microtime(true)];

        $this->store->saveBucket('key1', $bucket1, 60);
        $this->store->saveBucket('key2', $bucket2, 60);

        $retrieved1 = $this->store->getBucket('key1');
        $retrieved2 = $this->store->getBucket('key2');

        $this->assertEquals(1.0, $retrieved1['tokens']);
        $this->assertEquals(2.0, $retrieved2['tokens']);
    }

    public function test_update_existing_bucket(): void
    {
        $key = 'test-key';

        $this->store->saveBucket($key, ['tokens' => 1.0, 'last_refill' => microtime(true)], 60);
        $this->store->saveBucket($key, ['tokens' => 5.0, 'last_refill' => microtime(true)], 60);

        $retrieved = $this->store->getBucket($key);

        $this->assertEquals(5.0, $retrieved['tokens']);
    }

    public function test_clear_all_removes_all_buckets(): void
    {
        $this->store->saveBucket('key1', ['tokens' => 1.0, 'last_refill' => microtime(true)], 60);
        $this->store->saveBucket('key2', ['tokens' => 2.0, 'last_refill' => microtime(true)], 60);
        $this->store->saveBucket('key3', ['tokens' => 3.0, 'last_refill' => microtime(true)], 60);

        $this->store->clearAll();

        $this->assertNull($this->store->getBucket('key1'));
        $this->assertNull($this->store->getBucket('key2'));
        $this->assertNull($this->store->getBucket('key3'));
    }

    public function test_is_available_returns_bool(): void
    {
        $this->assertIsBool(APCuStore::isAvailable());
    }

    public function test_get_info_returns_array(): void
    {
        $info = $this->store->getInfo();

        $this->assertIsArray($info);
        $this->assertArrayHasKey('num_slots', $info);
        $this->assertArrayHasKey('num_hits', $info);
        $this->assertArrayHasKey('num_misses', $info);
    }

    public function test_prefix_isolates_keys(): void
    {
        $store1 = new APCuStore('prefix1:');
        $store2 = new APCuStore('prefix2:');

        $store1->saveBucket('same-key', ['tokens' => 1.0, 'last_refill' => microtime(true)], 60);
        $store2->saveBucket('same-key', ['tokens' => 2.0, 'last_refill' => microtime(true)], 60);

        $retrieved1 = $store1->getBucket('same-key');
        $retrieved2 = $store2->getBucket('same-key');

        $this->assertEquals(1.0, $retrieved1['tokens']);
        $this->assertEquals(2.0, $retrieved2['tokens']);

        $store1->clearAll();
        $store2->clearAll();
    }
}
