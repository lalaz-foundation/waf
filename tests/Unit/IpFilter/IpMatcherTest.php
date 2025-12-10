<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\IpFilter;

use Lalaz\Waf\IpFilter\IpMatcher;
use PHPUnit\Framework\TestCase;

class IpMatcherTest extends TestCase
{
    public function test_exact_match(): void
    {
        $this->assertTrue(IpMatcher::matches('192.168.1.1', '192.168.1.1'));
        $this->assertFalse(IpMatcher::matches('192.168.1.1', '192.168.1.2'));
    }

    public function test_cidr_ipv4_match(): void
    {
        // /24 = 256 IPs
        $this->assertTrue(IpMatcher::matchesCidr('192.168.1.1', '192.168.1.0/24'));
        $this->assertTrue(IpMatcher::matchesCidr('192.168.1.255', '192.168.1.0/24'));
        $this->assertFalse(IpMatcher::matchesCidr('192.168.2.1', '192.168.1.0/24'));

        // /16 = 65536 IPs
        $this->assertTrue(IpMatcher::matchesCidr('192.168.50.100', '192.168.0.0/16'));
        $this->assertFalse(IpMatcher::matchesCidr('192.169.0.1', '192.168.0.0/16'));

        // /8 = 16M IPs
        $this->assertTrue(IpMatcher::matchesCidr('10.50.100.200', '10.0.0.0/8'));
        $this->assertFalse(IpMatcher::matchesCidr('11.0.0.1', '10.0.0.0/8'));

        // /32 = single IP
        $this->assertTrue(IpMatcher::matchesCidr('192.168.1.1', '192.168.1.1/32'));
        $this->assertFalse(IpMatcher::matchesCidr('192.168.1.2', '192.168.1.1/32'));
    }

    public function test_cidr_ipv6_match(): void
    {
        $this->assertTrue(IpMatcher::matchesCidr('2001:db8::1', '2001:db8::/32'));
        $this->assertTrue(IpMatcher::matchesCidr('2001:db8:ffff::1', '2001:db8::/32'));
        $this->assertFalse(IpMatcher::matchesCidr('2001:db9::1', '2001:db8::/32'));
    }

    public function test_wildcard_match(): void
    {
        $this->assertTrue(IpMatcher::matchesWildcard('192.168.1.100', '192.168.1.*'));
        $this->assertTrue(IpMatcher::matchesWildcard('192.168.1.1', '192.168.1.*'));
        $this->assertFalse(IpMatcher::matchesWildcard('192.168.2.1', '192.168.1.*'));

        // Multiple wildcards
        $this->assertTrue(IpMatcher::matchesWildcard('192.168.1.100', '192.168.*.*'));
        $this->assertTrue(IpMatcher::matchesWildcard('192.168.50.200', '192.168.*.*'));
        $this->assertFalse(IpMatcher::matchesWildcard('192.169.1.1', '192.168.*.*'));
    }

    public function test_range_match(): void
    {
        $this->assertTrue(IpMatcher::matchesRange('192.168.1.50', '192.168.1.1-192.168.1.100'));
        $this->assertTrue(IpMatcher::matchesRange('192.168.1.1', '192.168.1.1-192.168.1.100'));
        $this->assertTrue(IpMatcher::matchesRange('192.168.1.100', '192.168.1.1-192.168.1.100'));
        $this->assertFalse(IpMatcher::matchesRange('192.168.1.101', '192.168.1.1-192.168.1.100'));
        $this->assertFalse(IpMatcher::matchesRange('192.168.2.50', '192.168.1.1-192.168.1.100'));
    }

    public function test_matches_any(): void
    {
        $patterns = [
            '192.168.1.1',
            '10.0.0.0/8',
            '172.16.*.*',
        ];

        $this->assertTrue(IpMatcher::matchesAny('192.168.1.1', $patterns));
        $this->assertTrue(IpMatcher::matchesAny('10.50.100.200', $patterns));
        $this->assertTrue(IpMatcher::matchesAny('172.16.50.100', $patterns));
        $this->assertFalse(IpMatcher::matchesAny('8.8.8.8', $patterns));
    }

    public function test_is_valid(): void
    {
        $this->assertTrue(IpMatcher::isValid('192.168.1.1'));
        $this->assertTrue(IpMatcher::isValid('::1'));
        $this->assertTrue(IpMatcher::isValid('2001:db8::1'));
        $this->assertFalse(IpMatcher::isValid('not-an-ip'));
        $this->assertFalse(IpMatcher::isValid('256.256.256.256'));
    }

    public function test_is_ipv4(): void
    {
        $this->assertTrue(IpMatcher::isIpv4('192.168.1.1'));
        $this->assertTrue(IpMatcher::isIpv4('10.0.0.1'));
        $this->assertFalse(IpMatcher::isIpv4('::1'));
        $this->assertFalse(IpMatcher::isIpv4('2001:db8::1'));
    }

    public function test_is_ipv6(): void
    {
        $this->assertTrue(IpMatcher::isIpv6('::1'));
        $this->assertTrue(IpMatcher::isIpv6('2001:db8::1'));
        $this->assertFalse(IpMatcher::isIpv6('192.168.1.1'));
    }

    public function test_is_private(): void
    {
        $this->assertTrue(IpMatcher::isPrivate('192.168.1.1'));
        $this->assertTrue(IpMatcher::isPrivate('10.0.0.1'));
        $this->assertTrue(IpMatcher::isPrivate('172.16.0.1'));
        $this->assertFalse(IpMatcher::isPrivate('8.8.8.8'));
        $this->assertFalse(IpMatcher::isPrivate('1.1.1.1'));
    }

    public function test_is_loopback(): void
    {
        $this->assertTrue(IpMatcher::isLoopback('127.0.0.1'));
        $this->assertTrue(IpMatcher::isLoopback('127.0.0.100'));
        $this->assertTrue(IpMatcher::isLoopback('::1'));
        $this->assertFalse(IpMatcher::isLoopback('192.168.1.1'));
        $this->assertFalse(IpMatcher::isLoopback('8.8.8.8'));
    }

    public function test_matches_with_automatic_detection(): void
    {
        // Should detect CIDR
        $this->assertTrue(IpMatcher::matches('192.168.1.50', '192.168.1.0/24'));

        // Should detect wildcard
        $this->assertTrue(IpMatcher::matches('192.168.1.50', '192.168.1.*'));

        // Should detect range
        $this->assertTrue(IpMatcher::matches('192.168.1.50', '192.168.1.1-192.168.1.100'));

        // Should do exact match
        $this->assertTrue(IpMatcher::matches('192.168.1.50', '192.168.1.50'));
    }

    public function test_invalid_cidr_returns_false(): void
    {
        $this->assertFalse(IpMatcher::matchesCidr('192.168.1.1', '192.168.1.0/33'));
        $this->assertFalse(IpMatcher::matchesCidr('192.168.1.1', '192.168.1.0/-1'));
        $this->assertFalse(IpMatcher::matchesCidr('not-an-ip', '192.168.1.0/24'));
        $this->assertFalse(IpMatcher::matchesCidr('192.168.1.1', 'not-a-cidr/24'));
    }

    public function test_invalid_range_returns_false(): void
    {
        $this->assertFalse(IpMatcher::matchesRange('not-an-ip', '192.168.1.1-192.168.1.100'));
        $this->assertFalse(IpMatcher::matchesRange('192.168.1.50', 'not-an-ip-192.168.1.100'));
        $this->assertFalse(IpMatcher::matchesRange('192.168.1.50', '192.168.1.1-not-an-ip'));
    }
}
