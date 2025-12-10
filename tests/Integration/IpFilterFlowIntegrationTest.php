<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Integration;

use Lalaz\Waf\Tests\Common\WafIntegrationTestCase;
use Lalaz\Waf\IpFilter\IpMatcher;
use Lalaz\Waf\IpFilter\IpList;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Integration tests for complete IP filtering flows.
 *
 * These tests verify the complete IP filtering pipeline including:
 * - CIDR matching
 * - Wildcard matching
 * - Range matching
 * - IP list management
 * - Private/public IP detection
 *
 * @package lalaz/waf
 */
final class IpFilterFlowIntegrationTest extends WafIntegrationTestCase
{
    // =========================================================================
    // CIDR Matching Tests
    // =========================================================================

    #[Test]
    #[DataProvider('cidrMatchProvider')]
    public function it_matches_ips_in_cidr_range(string $ip, string $cidr, bool $expected): void
    {
        $result = IpMatcher::matchesCidr($ip, $cidr);
        $this->assertEquals($expected, $result);
    }

    public static function cidrMatchProvider(): array
    {
        return [
            // Class C (/24)
            'First IP in /24 range' => ['192.168.1.0', '192.168.1.0/24', true],
            'Last IP in /24 range' => ['192.168.1.255', '192.168.1.0/24', true],
            'Middle IP in /24 range' => ['192.168.1.100', '192.168.1.0/24', true],
            'IP outside /24 range' => ['192.168.2.1', '192.168.1.0/24', false],

            // Class B (/16)
            'IP in /16 range' => ['172.16.50.100', '172.16.0.0/16', true],
            'IP outside /16 range' => ['172.17.0.1', '172.16.0.0/16', false],

            // Class A (/8)
            'IP in /8 range' => ['10.255.255.255', '10.0.0.0/8', true],
            'IP outside /8 range' => ['11.0.0.1', '10.0.0.0/8', false],

            // Smaller ranges
            'IP in /30 range' => ['192.168.1.1', '192.168.1.0/30', true],
            'IP outside /30 range' => ['192.168.1.5', '192.168.1.0/30', false],

            // Single IP (/32)
            'Exact match /32' => ['192.168.1.1', '192.168.1.1/32', true],
            'No match /32' => ['192.168.1.2', '192.168.1.1/32', false],
        ];
    }

    // =========================================================================
    // Wildcard Matching Tests
    // =========================================================================

    #[Test]
    #[DataProvider('wildcardMatchProvider')]
    public function it_matches_ips_with_wildcard_pattern(string $ip, string $pattern, bool $expected): void
    {
        $result = IpMatcher::matchesWildcard($ip, $pattern);
        $this->assertEquals($expected, $result);
    }

    public static function wildcardMatchProvider(): array
    {
        return [
            // Last octet wildcard
            'Match last octet wildcard' => ['192.168.1.100', '192.168.1.*', true],
            'No match last octet wildcard' => ['192.168.2.100', '192.168.1.*', false],

            // Two octet wildcard
            'Match two octet wildcard' => ['192.168.50.100', '192.168.*.*', true],
            'No match two octet wildcard' => ['192.169.1.1', '192.168.*.*', false],

            // First octet wildcard
            'Match first octet wildcard' => ['10.168.1.100', '*.168.1.100', true],
            'No match first octet wildcard' => ['10.169.1.100', '*.168.1.100', false],

            // All wildcards
            'All wildcards match everything' => ['1.2.3.4', '*.*.*.*', true],

            // Exact match (no wildcard)
            'Exact match' => ['192.168.1.1', '192.168.1.1', true],
            'No exact match' => ['192.168.1.2', '192.168.1.1', false],
        ];
    }

    // =========================================================================
    // Range Matching Tests
    // =========================================================================

    #[Test]
    #[DataProvider('rangeMatchProvider')]
    public function it_matches_ips_in_range(string $ip, string $range, bool $expected): void
    {
        $result = IpMatcher::matchesRange($ip, $range);
        $this->assertEquals($expected, $result);
    }

    public static function rangeMatchProvider(): array
    {
        return [
            'Start of range' => ['192.168.1.1', '192.168.1.1-192.168.1.100', true],
            'End of range' => ['192.168.1.100', '192.168.1.1-192.168.1.100', true],
            'Middle of range' => ['192.168.1.50', '192.168.1.1-192.168.1.100', true],
            'Before range' => ['192.168.1.0', '192.168.1.1-192.168.1.100', false],
            'After range' => ['192.168.1.101', '192.168.1.1-192.168.1.100', false],

            // Cross octet range
            'Cross octet range' => ['192.168.2.1', '192.168.1.200-192.168.2.50', true],
        ];
    }

    // =========================================================================
    // Generic Match Tests
    // =========================================================================

    #[Test]
    public function it_auto_detects_pattern_type(): void
    {
        // CIDR
        $this->assertTrue(IpMatcher::matches('192.168.1.100', '192.168.1.0/24'));

        // Wildcard
        $this->assertTrue(IpMatcher::matches('192.168.1.100', '192.168.1.*'));

        // Range
        $this->assertTrue(IpMatcher::matches('192.168.1.50', '192.168.1.1-192.168.1.100'));

        // Exact
        $this->assertTrue(IpMatcher::matches('192.168.1.1', '192.168.1.1'));
    }

    // =========================================================================
    // Private/Public IP Detection Tests
    // =========================================================================

    #[Test]
    #[DataProvider('privateIpProvider')]
    public function it_detects_private_ips(string $ip): void
    {
        $this->assertTrue(IpMatcher::isPrivate($ip));
    }

    public static function privateIpProvider(): array
    {
        return [
            // 10.0.0.0/8
            '10.0.0.1' => ['10.0.0.1'],
            '10.255.255.255' => ['10.255.255.255'],
            '10.100.50.25' => ['10.100.50.25'],

            // 172.16.0.0/12
            '172.16.0.1' => ['172.16.0.1'],
            '172.31.255.255' => ['172.31.255.255'],
            '172.20.10.5' => ['172.20.10.5'],

            // 192.168.0.0/16
            '192.168.0.1' => ['192.168.0.1'],
            '192.168.255.255' => ['192.168.255.255'],
            '192.168.1.100' => ['192.168.1.100'],
        ];
    }

    #[Test]
    #[DataProvider('publicIpProvider')]
    public function it_detects_public_ips(string $ip): void
    {
        $this->assertFalse(IpMatcher::isPrivate($ip));
    }

    public static function publicIpProvider(): array
    {
        return [
            '8.8.8.8' => ['8.8.8.8'],
            '1.1.1.1' => ['1.1.1.1'],
            '203.0.113.1' => ['203.0.113.1'],
            '198.51.100.1' => ['198.51.100.1'],
            '172.32.0.1 (just outside 172.16-31)' => ['172.32.0.1'],
            '11.0.0.1 (just outside 10.x.x.x)' => ['11.0.0.1'],
        ];
    }

    // =========================================================================
    // Loopback Detection Tests
    // =========================================================================

    #[Test]
    #[DataProvider('loopbackIpProvider')]
    public function it_detects_loopback_ips(string $ip): void
    {
        $this->assertTrue(IpMatcher::isLoopback($ip));
    }

    public static function loopbackIpProvider(): array
    {
        return [
            '127.0.0.1' => ['127.0.0.1'],
            '127.0.0.2' => ['127.0.0.2'],
            '127.255.255.255' => ['127.255.255.255'],
            '::1 (IPv6)' => ['::1'],
        ];
    }

    // =========================================================================
    // IP List Tests
    // =========================================================================

    #[Test]
    public function ip_list_supports_multiple_pattern_types(): void
    {
        $list = new IpList('test', [
            '192.168.1.1',           // Exact
            '10.0.0.0/8',            // CIDR
            '172.16.*.*',            // Wildcard
            '203.0.113.1-203.0.113.50', // Range
        ]);

        // Should match exact
        $this->assertTrue($list->contains('192.168.1.1'));
        $this->assertFalse($list->contains('192.168.1.2'));

        // Should match CIDR
        $this->assertTrue($list->contains('10.0.0.1'));
        $this->assertTrue($list->contains('10.255.255.255'));

        // Should match wildcard
        $this->assertTrue($list->contains('172.16.1.1'));
        $this->assertTrue($list->contains('172.16.255.255'));

        // Should match range
        $this->assertTrue($list->contains('203.0.113.25'));
        $this->assertFalse($list->contains('203.0.113.100'));
    }

    #[Test]
    public function ip_list_add_and_remove(): void
    {
        $list = new IpList('test');

        // Add IPs
        $list->add('192.168.1.1');
        $list->add('10.0.0.0/8');

        $this->assertTrue($list->contains('192.168.1.1'));
        $this->assertTrue($list->contains('10.0.0.1'));
        $this->assertEquals(2, $list->count());

        // Remove IP
        $list->remove('192.168.1.1');

        $this->assertFalse($list->contains('192.168.1.1'));
        $this->assertTrue($list->contains('10.0.0.1'));
        $this->assertEquals(1, $list->count());
    }

    #[Test]
    public function ip_list_clear(): void
    {
        $list = new IpList('test', ['192.168.1.1', '10.0.0.1', '172.16.0.1']);

        $this->assertEquals(3, $list->count());

        $list->clear();

        $this->assertEquals(0, $list->count());
        $this->assertFalse($list->contains('192.168.1.1'));
    }

    #[Test]
    public function ip_list_triggers_persist_callback(): void
    {
        $persisted = [];

        $list = new IpList('test');
        $list->onPersist(function (string $name, array $patterns) use (&$persisted) {
            $persisted = ['name' => $name, 'patterns' => $patterns];
        });

        $list->add('192.168.1.1');

        $this->assertEquals('test', $persisted['name']);
        $this->assertContains('192.168.1.1', $persisted['patterns']);
    }

    #[Test]
    public function ip_list_all_returns_all_entries(): void
    {
        $ips = ['192.168.1.1', '10.0.0.0/8', '172.16.*.*'];
        $list = new IpList('test', $ips);

        $this->assertEquals($ips, $list->all());
    }

    #[Test]
    public function ip_list_has_checks_exact_pattern(): void
    {
        $list = new IpList('test', ['192.168.1.1', '10.0.0.0/8']);

        $this->assertTrue($list->has('192.168.1.1'));
        $this->assertTrue($list->has('10.0.0.0/8'));
        $this->assertFalse($list->has('10.0.0.1')); // contains works, has doesn't
    }

    #[Test]
    public function ip_list_is_empty(): void
    {
        $emptyList = new IpList('empty');
        $this->assertTrue($emptyList->isEmpty());

        $fullList = new IpList('full', ['192.168.1.1']);
        $this->assertFalse($fullList->isEmpty());
    }

    #[Test]
    public function ip_list_from_array(): void
    {
        $list = IpList::fromArray(['192.168.1.1', '10.0.0.0/8'], 'fromArray');

        $this->assertEquals('fromArray', $list->getName());
        $this->assertEquals(2, $list->count());
    }

    // =========================================================================
    // Use Case Tests
    // =========================================================================

    #[Test]
    public function use_case_whitelist_internal_network(): void
    {
        $whitelist = new IpList('whitelist', [
            '192.168.0.0/16',  // Office network
            '10.0.0.0/8',      // VPN network
            '127.0.0.1',       // Localhost
        ]);

        // Internal IPs should be allowed
        $this->assertTrue($whitelist->contains('192.168.1.100'));
        $this->assertTrue($whitelist->contains('10.50.25.1'));
        $this->assertTrue($whitelist->contains('127.0.0.1'));

        // External IPs should be blocked
        $this->assertFalse($whitelist->contains('8.8.8.8'));
        $this->assertFalse($whitelist->contains('203.0.113.1'));
    }

    #[Test]
    public function use_case_blacklist_known_bad_actors(): void
    {
        $blacklist = new IpList('blacklist', [
            '203.0.113.0/24',  // Known malicious network
            '198.51.100.50',   // Known attacker IP
        ]);

        // Bad actors should be blocked
        $this->assertTrue($blacklist->contains('203.0.113.1'));
        $this->assertTrue($blacklist->contains('203.0.113.255'));
        $this->assertTrue($blacklist->contains('198.51.100.50'));

        // Good IPs should be allowed
        $this->assertFalse($blacklist->contains('8.8.8.8'));
        $this->assertFalse($blacklist->contains('192.168.1.1'));
    }

    #[Test]
    public function use_case_admin_ip_restriction(): void
    {
        // Only specific IPs can access admin
        $adminIps = new IpList('adminIps', [
            '192.168.1.100',        // Office admin workstation
            '10.0.0.50-10.0.0.60',  // IT department range
        ]);

        // Admin can access
        $this->assertTrue($adminIps->contains('192.168.1.100'));
        $this->assertTrue($adminIps->contains('10.0.0.55'));

        // Others cannot
        $this->assertFalse($adminIps->contains('192.168.1.101'));
        $this->assertFalse($adminIps->contains('10.0.0.49'));
        $this->assertFalse($adminIps->contains('10.0.0.61'));
    }
}
