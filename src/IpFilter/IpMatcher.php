<?php

declare(strict_types=1);

namespace Lalaz\Waf\IpFilter;

/**
 * IP Matcher utility for matching IPs against patterns.
 *
 * Supports:
 * - Exact IP matching (192.168.1.1)
 * - CIDR notation (192.168.1.0/24)
 * - Wildcard patterns (192.168.1.*)
 * - Range notation (192.168.1.1-192.168.1.100)
 *
 * @package lalaz/waf
 */
final class IpMatcher
{
    /**
     * Check if an IP matches a pattern.
     *
     * @param string $ip The IP address to check.
     * @param string $pattern The pattern to match against.
     * @return bool True if the IP matches the pattern.
     */
    public static function matches(string $ip, string $pattern): bool
    {
        $ip = trim($ip);
        $pattern = trim($pattern);

        // Exact match
        if ($ip === $pattern) {
            return true;
        }

        // CIDR notation (e.g., 192.168.1.0/24)
        if (str_contains($pattern, '/')) {
            return self::matchesCidr($ip, $pattern);
        }

        // Wildcard pattern (e.g., 192.168.1.*)
        if (str_contains($pattern, '*')) {
            return self::matchesWildcard($ip, $pattern);
        }

        // Range notation (e.g., 192.168.1.1-192.168.1.100)
        if (str_contains($pattern, '-')) {
            return self::matchesRange($ip, $pattern);
        }

        return false;
    }

    /**
     * Check if an IP matches any pattern in a list.
     *
     * @param string $ip The IP address to check.
     * @param array<string> $patterns The patterns to match against.
     * @return bool True if the IP matches any pattern.
     */
    public static function matchesAny(string $ip, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (self::matches($ip, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if an IP matches a CIDR notation pattern.
     *
     * @param string $ip The IP address to check.
     * @param string $cidr The CIDR pattern (e.g., 192.168.1.0/24).
     * @return bool True if the IP is within the CIDR range.
     */
    public static function matchesCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        // Handle IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::matchesCidrIpv6($ip, $subnet, $bits);
        }

        // Handle IPv4
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $mask = -1 << (32 - $bits);

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    /**
     * Check if an IPv6 address matches a CIDR notation pattern.
     *
     * @param string $ip The IPv6 address to check.
     * @param string $subnet The subnet address.
     * @param int $bits The number of bits in the mask.
     * @return bool True if the IP is within the CIDR range.
     */
    private static function matchesCidrIpv6(string $ip, string $subnet, int $bits): bool
    {
        if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return false;
        }

        if ($bits < 0 || $bits > 128) {
            return false;
        }

        $ipBinary = inet_pton($ip);
        $subnetBinary = inet_pton($subnet);

        if ($ipBinary === false || $subnetBinary === false) {
            return false;
        }

        // Compare bit by bit
        $fullBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        // Compare full bytes
        for ($i = 0; $i < $fullBytes; $i++) {
            if ($ipBinary[$i] !== $subnetBinary[$i]) {
                return false;
            }
        }

        // Compare remaining bits
        if ($remainingBits > 0 && $fullBytes < 16) {
            $mask = 0xFF << (8 - $remainingBits);
            if ((ord($ipBinary[$fullBytes]) & $mask) !== (ord($subnetBinary[$fullBytes]) & $mask)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if an IP matches a wildcard pattern.
     *
     * @param string $ip The IP address to check.
     * @param string $pattern The wildcard pattern (e.g., 192.168.1.*).
     * @return bool True if the IP matches the pattern.
     */
    public static function matchesWildcard(string $ip, string $pattern): bool
    {
        // Convert wildcard pattern to regex
        $regex = '/^' . str_replace(
            ['\\*', '\\?'],
            ['[0-9]+', '[0-9]'],
            preg_quote($pattern, '/')
        ) . '$/';

        return (bool) preg_match($regex, $ip);
    }

    /**
     * Check if an IP is within a range.
     *
     * @param string $ip The IP address to check.
     * @param string $range The range (e.g., 192.168.1.1-192.168.1.100).
     * @return bool True if the IP is within the range.
     */
    public static function matchesRange(string $ip, string $range): bool
    {
        if (!str_contains($range, '-')) {
            return $ip === $range;
        }

        [$start, $end] = explode('-', $range, 2);
        $start = trim($start);
        $end = trim($end);

        // Validate IPs
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        if (!filter_var($start, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        if (!filter_var($end, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $ipLong = ip2long($ip);
        $startLong = ip2long($start);
        $endLong = ip2long($end);

        return $ipLong >= $startLong && $ipLong <= $endLong;
    }

    /**
     * Validate an IP address.
     *
     * @param string $ip The IP address to validate.
     * @return bool True if the IP is valid.
     */
    public static function isValid(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Check if an IP is IPv4.
     *
     * @param string $ip The IP address to check.
     * @return bool True if the IP is IPv4.
     */
    public static function isIpv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * Check if an IP is IPv6.
     *
     * @param string $ip The IP address to check.
     * @return bool True if the IP is IPv6.
     */
    public static function isIpv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Check if an IP is a private/local address.
     *
     * @param string $ip The IP address to check.
     * @return bool True if the IP is private.
     */
    public static function isPrivate(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false && self::isValid($ip);
    }

    /**
     * Check if an IP is a loopback address.
     *
     * @param string $ip The IP address to check.
     * @return bool True if the IP is loopback.
     */
    public static function isLoopback(string $ip): bool
    {
        if (self::isIpv4($ip)) {
            return self::matchesCidr($ip, '127.0.0.0/8');
        }

        if (self::isIpv6($ip)) {
            return $ip === '::1' || strtolower($ip) === '0000:0000:0000:0000:0000:0000:0000:0001';
        }

        return false;
    }
}
