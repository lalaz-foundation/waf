<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\RateLimit\Stores;

use Lalaz\Waf\RateLimit\Stores\RedisStore;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for RedisStore.
 *
 * These tests require a running Redis instance.
 * Skip with: --exclude-group redis
 *
 * @group redis
 */
class RedisStoreTest extends TestCase
{
    private ?RedisStore $store = null;

    protected function setUp(): void
    {
        if (!RedisStore::isAvailable()) {
            $this->markTestSkipped('Redis is not available (neither phpredis nor predis)');
        }

        try {
            $this->store = new RedisStore([
                'host' => getenv('REDIS_HOST') ?: '127.0.0.1',
                'port' => (int) (getenv('REDIS_PORT') ?: 6379),
                'database' => 15, // Use database 15 for tests
            ], 'test:rl:');

            if (!$this->store->ping()) {
                $this->markTestSkipped('Could not connect to Redis');
            }

            $this->store->clearAll();
        } catch (\Throwable $e) {
            $this->markTestSkipped('Redis connection failed: ' . $e->getMessage());
        }
    }

    protected function tearDown(): void
    {
        if ($this->store !== null) {
            try {
                $this->store->clearAll();
            } catch (\Throwable) {
                // Ignore cleanup errors
            }
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

        $deleted = $this->store->clearAll();

        $this->assertGreaterThanOrEqual(3, $deleted);
        $this->assertNull($this->store->getBucket('key1'));
        $this->assertNull($this->store->getBucket('key2'));
        $this->assertNull($this->store->getBucket('key3'));
    }

    public function test_is_available_returns_bool(): void
    {
        $this->assertIsBool(RedisStore::isAvailable());
    }

    public function test_ping_returns_true(): void
    {
        $this->assertTrue($this->store->ping());
    }

    public function test_get_info_returns_array(): void
    {
        $info = $this->store->getInfo();

        $this->assertIsArray($info);
    }

    public function test_get_info_with_section(): void
    {
        $info = $this->store->getInfo('server');

        $this->assertIsArray($info);
    }

    public function test_get_client_returns_redis_instance(): void
    {
        $client = $this->store->getClient();

        $this->assertIsObject($client);
    }

    public function test_prefix_isolates_keys(): void
    {
        $config = [
            'host' => getenv('REDIS_HOST') ?: '127.0.0.1',
            'port' => (int) (getenv('REDIS_PORT') ?: 6379),
            'database' => 15,
        ];

        $store1 = new RedisStore($config, 'prefix1:');
        $store2 = new RedisStore($config, 'prefix2:');

        $store1->saveBucket('same-key', ['tokens' => 1.0, 'last_refill' => microtime(true)], 60);
        $store2->saveBucket('same-key', ['tokens' => 2.0, 'last_refill' => microtime(true)], 60);

        $retrieved1 = $store1->getBucket('same-key');
        $retrieved2 = $store2->getBucket('same-key');

        $this->assertEquals(1.0, $retrieved1['tokens']);
        $this->assertEquals(2.0, $retrieved2['tokens']);

        $store1->clearAll();
        $store2->clearAll();
    }

    public function test_from_connection_works(): void
    {
        $client = $this->store->getClient();

        $newStore = RedisStore::fromConnection($client, 'fromconn:');

        $newStore->saveBucket('test', ['tokens' => 10.0, 'last_refill' => microtime(true)], 60);

        $retrieved = $newStore->getBucket('test');
        $this->assertEquals(10.0, $retrieved['tokens']);

        $newStore->clearAll();
    }
}
