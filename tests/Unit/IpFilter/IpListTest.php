<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\IpFilter;

use Lalaz\Waf\IpFilter\IpList;
use PHPUnit\Framework\TestCase;

class IpListTest extends TestCase
{
    public function test_creates_empty_list(): void
    {
        $list = new IpList();

        $this->assertTrue($list->isEmpty());
        $this->assertEquals(0, $list->count());
    }

    public function test_creates_list_with_patterns(): void
    {
        $list = new IpList('test', ['192.168.1.1', '10.0.0.0/8']);

        $this->assertFalse($list->isEmpty());
        $this->assertEquals(2, $list->count());
    }

    public function test_add_pattern(): void
    {
        $list = new IpList();
        $list->add('192.168.1.1');

        $this->assertEquals(1, $list->count());
        $this->assertTrue($list->has('192.168.1.1'));
    }

    public function test_add_duplicate_pattern_is_ignored(): void
    {
        $list = new IpList();
        $list->add('192.168.1.1');
        $list->add('192.168.1.1');

        $this->assertEquals(1, $list->count());
    }

    public function test_add_many_patterns(): void
    {
        $list = new IpList();
        $list->addMany(['192.168.1.1', '192.168.1.2', '192.168.1.3']);

        $this->assertEquals(3, $list->count());
    }

    public function test_remove_pattern(): void
    {
        $list = new IpList('test', ['192.168.1.1', '192.168.1.2']);
        $list->remove('192.168.1.1');

        $this->assertEquals(1, $list->count());
        $this->assertFalse($list->has('192.168.1.1'));
        $this->assertTrue($list->has('192.168.1.2'));
    }

    public function test_remove_nonexistent_pattern_is_safe(): void
    {
        $list = new IpList('test', ['192.168.1.1']);
        $list->remove('192.168.1.2');

        $this->assertEquals(1, $list->count());
    }

    public function test_remove_many_patterns(): void
    {
        $list = new IpList('test', ['192.168.1.1', '192.168.1.2', '192.168.1.3']);
        $list->removeMany(['192.168.1.1', '192.168.1.3']);

        $this->assertEquals(1, $list->count());
        $this->assertTrue($list->has('192.168.1.2'));
    }

    public function test_contains_exact_ip(): void
    {
        $list = new IpList('test', ['192.168.1.1']);

        $this->assertTrue($list->contains('192.168.1.1'));
        $this->assertFalse($list->contains('192.168.1.2'));
    }

    public function test_contains_cidr_range(): void
    {
        $list = new IpList('test', ['192.168.1.0/24']);

        $this->assertTrue($list->contains('192.168.1.1'));
        $this->assertTrue($list->contains('192.168.1.255'));
        $this->assertFalse($list->contains('192.168.2.1'));
    }

    public function test_contains_wildcard(): void
    {
        $list = new IpList('test', ['192.168.1.*']);

        $this->assertTrue($list->contains('192.168.1.1'));
        $this->assertTrue($list->contains('192.168.1.100'));
        $this->assertFalse($list->contains('192.168.2.1'));
    }

    public function test_contains_range(): void
    {
        $list = new IpList('test', ['192.168.1.1-192.168.1.100']);

        $this->assertTrue($list->contains('192.168.1.50'));
        $this->assertFalse($list->contains('192.168.1.150'));
    }

    public function test_clear_removes_all_patterns(): void
    {
        $list = new IpList('test', ['192.168.1.1', '192.168.1.2']);
        $list->clear();

        $this->assertTrue($list->isEmpty());
        $this->assertEquals(0, $list->count());
    }

    public function test_all_returns_patterns(): void
    {
        $patterns = ['192.168.1.1', '10.0.0.0/8'];
        $list = new IpList('test', $patterns);

        $this->assertEquals($patterns, $list->all());
    }

    public function test_get_name(): void
    {
        $list = new IpList('my-list');

        $this->assertEquals('my-list', $list->getName());
    }

    public function test_from_array_factory(): void
    {
        $list = IpList::fromArray(['192.168.1.1', '10.0.0.0/8'], 'test');

        $this->assertEquals('test', $list->getName());
        $this->assertEquals(2, $list->count());
    }

    public function test_on_persist_callback(): void
    {
        $persisted = null;

        $list = new IpList('test');
        $list->onPersist(function ($name, $patterns) use (&$persisted) {
            $persisted = ['name' => $name, 'patterns' => $patterns];
        });

        $list->add('192.168.1.1');

        $this->assertNotNull($persisted);
        $this->assertEquals('test', $persisted['name']);
        $this->assertEquals(['192.168.1.1'], $persisted['patterns']);
    }

    public function test_methods_are_chainable(): void
    {
        $list = new IpList();

        $result = $list
            ->add('192.168.1.1')
            ->addMany(['192.168.1.2', '192.168.1.3'])
            ->remove('192.168.1.1')
            ->clear();

        $this->assertSame($list, $result);
    }

    public function test_from_file_handles_missing_file(): void
    {
        $list = IpList::fromFile('/nonexistent/file.txt');

        $this->assertTrue($list->isEmpty());
    }

    public function test_from_file_and_to_file(): void
    {
        $tempFile = sys_get_temp_dir() . '/ip_list_test_' . uniqid() . '.txt';

        try {
            // Create and save
            $list = new IpList('test', ['192.168.1.1', '10.0.0.0/8']);
            $result = $list->toFile($tempFile);

            $this->assertTrue($result);
            $this->assertFileExists($tempFile);

            // Load and verify
            $loaded = IpList::fromFile($tempFile, 'loaded');

            $this->assertEquals(2, $loaded->count());
            $this->assertTrue($loaded->has('192.168.1.1'));
            $this->assertTrue($loaded->has('10.0.0.0/8'));
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    public function test_from_file_ignores_comments_and_empty_lines(): void
    {
        $tempFile = sys_get_temp_dir() . '/ip_list_test_' . uniqid() . '.txt';

        try {
            file_put_contents($tempFile, "# Comment\n\n192.168.1.1\n# Another comment\n10.0.0.0/8\n");

            $list = IpList::fromFile($tempFile);

            $this->assertEquals(2, $list->count());
            $this->assertTrue($list->has('192.168.1.1'));
            $this->assertTrue($list->has('10.0.0.0/8'));
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }
}
