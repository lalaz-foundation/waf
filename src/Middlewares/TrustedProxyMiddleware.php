<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Waf\IpFilter\IpMatcher;
use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * Trusted Proxy Middleware.
 *
 * Resolves the real client IP address when behind reverse proxies,
 * load balancers, or CDNs (Nginx, Cloudflare, AWS ALB, etc.).
 *
 * This middleware should be registered EARLY in the middleware stack
 * so that subsequent middlewares (Rate Limiting, IP Filtering, Geo Blocking, etc.)
 * have access to the real client IP.
 *
 * Supported headers:
 * - X-Forwarded-For (standard)
 * - X-Real-IP (Nginx)
 * - CF-Connecting-IP (Cloudflare)
 * - True-Client-IP (Cloudflare Enterprise, Akamai)
 * - X-Client-IP (some proxies)
 * - Forwarded (RFC 7239)
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 * @link https://lalaz.dev
 */
final class TrustedProxyMiddleware implements MiddlewareInterface
{
    /**
     * Known proxy header names in priority order.
     */
    public const HEADER_X_FORWARDED_FOR = 'X-Forwarded-For';
    public const HEADER_X_REAL_IP = 'X-Real-IP';
    public const HEADER_CF_CONNECTING_IP = 'CF-Connecting-IP';
    public const HEADER_TRUE_CLIENT_IP = 'True-Client-IP';
    public const HEADER_X_CLIENT_IP = 'X-Client-IP';
    public const HEADER_FORWARDED = 'Forwarded';

    /**
     * Cloudflare IP ranges (IPv4).
     * @see https://www.cloudflare.com/ips-v4
     */
    private const CLOUDFLARE_IPS_V4 = [
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
    ];

    /**
     * Cloudflare IP ranges (IPv6).
     * @see https://www.cloudflare.com/ips-v6
     */
    private const CLOUDFLARE_IPS_V6 = [
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    /**
     * AWS CloudFront IP ranges are dynamic.
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
     */
    private const AWS_CLOUDFRONT_RANGES_URL = 'https://ip-ranges.amazonaws.com/ip-ranges.json';

    /**
     * Private/internal IP ranges.
     */
    private const PRIVATE_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '::1/128',
        'fc00::/7',
        'fe80::/10',
    ];

    /**
     * @var array<string> Trusted proxy IP addresses or CIDR ranges.
     */
    private array $trustedProxies;

    /**
     * @var array<string> Headers to check for client IP (in priority order).
     */
    private array $headers;

    /**
     * @var bool Whether to trust all private/internal IPs as proxies.
     */
    private bool $trustPrivateNetworks;

    /**
     * @var string|null Attribute name to store resolved IP in request.
     */
    private ?string $ipAttribute;

    /**
     * @var callable|null Custom IP resolver.
     */
    private $customResolver;

    /**
     * Create a new TrustedProxyMiddleware.
     *
     * @param array<string> $trustedProxies Trusted proxy IPs/CIDR ranges.
     * @param array<string> $headers Headers to check (in priority order).
     * @param bool $trustPrivateNetworks Trust all private IPs as proxies.
     * @param string|null $ipAttribute Request attribute to store resolved IP.
     */
    public function __construct(
        array $trustedProxies = [],
        array $headers = [
            self::HEADER_CF_CONNECTING_IP,
            self::HEADER_TRUE_CLIENT_IP,
            self::HEADER_X_REAL_IP,
            self::HEADER_X_FORWARDED_FOR,
            self::HEADER_X_CLIENT_IP,
            self::HEADER_FORWARDED,
        ],
        bool $trustPrivateNetworks = false,
        ?string $ipAttribute = 'client_ip',
    ) {
        $this->trustedProxies = $trustedProxies;
        $this->headers = $headers;
        $this->trustPrivateNetworks = $trustPrivateNetworks;
        $this->ipAttribute = $ipAttribute;
        $this->customResolver = null;
    }

    /**
     * Handle the request.
     */
    public function handle(
        RequestInterface $req,
        ResponseInterface $res,
        callable $next,
    ): mixed {
        $directIp = $req->ip() ?? '0.0.0.0';
        $clientIp = $directIp;

        // Only resolve from headers if direct IP is from trusted proxy
        if ($this->isTrustedProxy($directIp)) {
            $clientIp = $this->resolveClientIp($req, $directIp);
        }

        // Store resolved IP in request attribute if configured
        // Note: setAttribute is provided by HasAttributes trait, not by RequestInterface
        if ($this->ipAttribute !== null && method_exists($req, 'setAttribute')) {
            $req->setAttribute($this->ipAttribute, $clientIp);
        }

        return $next($req, $res);
    }

    /**
     * Check if an IP is from a trusted proxy.
     */
    private function isTrustedProxy(string $ip): bool
    {
        // Trust all if no proxies configured
        if (empty($this->trustedProxies) && !$this->trustPrivateNetworks) {
            return false;
        }

        // Check private networks
        if ($this->trustPrivateNetworks && IpMatcher::matchesAny($ip, self::PRIVATE_RANGES)) {
            return true;
        }

        // Check configured trusted proxies
        if (!empty($this->trustedProxies) && IpMatcher::matchesAny($ip, $this->trustedProxies)) {
            return true;
        }

        return false;
    }

    /**
     * Resolve the real client IP from headers.
     */
    private function resolveClientIp(RequestInterface $req, string $fallback): string
    {
        // Use custom resolver if set
        if ($this->customResolver !== null) {
            $resolved = ($this->customResolver)($req);
            if ($resolved !== null && $resolved !== '') {
                return $resolved;
            }
        }

        // Check headers in priority order
        foreach ($this->headers as $header) {
            $value = $req->header($header);
            if ($value === null || $value === '') {
                continue;
            }

            $ip = $this->parseHeaderValue($header, $value);
            if ($ip !== null && $this->isValidPublicIp($ip)) {
                return $ip;
            }
        }

        return $fallback;
    }

    /**
     * Parse IP from a header value.
     */
    private function parseHeaderValue(string $header, string $value): ?string
    {
        // Handle Forwarded header (RFC 7239)
        if (strcasecmp($header, self::HEADER_FORWARDED) === 0) {
            return $this->parseForwardedHeader($value);
        }

        // Handle X-Forwarded-For (comma-separated list)
        if (strcasecmp($header, self::HEADER_X_FORWARDED_FOR) === 0) {
            $ips = array_map('trim', explode(',', $value));
            // Return leftmost (original client) IP
            return $ips[0] ?: null;
        }

        // Single IP headers
        return trim($value) ?: null;
    }

    /**
     * Parse the Forwarded header (RFC 7239).
     * Example: for=192.0.2.60;proto=http;by=203.0.113.43
     */
    private function parseForwardedHeader(string $value): ?string
    {
        // Get first forwarded element
        $parts = explode(',', $value);
        $first = trim($parts[0]);

        // Parse key=value pairs
        $pairs = explode(';', $first);
        foreach ($pairs as $pair) {
            $pair = trim($pair);
            if (stripos($pair, 'for=') === 0) {
                $ip = substr($pair, 4);
                // Remove quotes and brackets
                $ip = trim($ip, '"\'[]');
                // Handle IPv6 with port
                if (str_contains($ip, ']:')) {
                    $ip = substr($ip, 0, (int)strrpos($ip, ']:') + 1);
                    $ip = trim($ip, '[]');
                }
                return $ip ?: null;
            }
        }

        return null;
    }

    /**
     * Check if an IP is a valid public (non-private) IP.
     */
    private function isValidPublicIp(string $ip): bool
    {
        // Validate IP format
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        // Check if it's a private IP
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            // It's a private/reserved IP - still valid but not "public"
            // We accept it because the client might be on a private network
            return true;
        }

        return true;
    }

    /**
     * Set a custom IP resolver.
     *
     * @param callable(RequestInterface): ?string $resolver
     * @return self
     */
    public function withResolver(callable $resolver): self
    {
        $clone = clone $this;
        $clone->customResolver = $resolver;
        return $clone;
    }

    /**
     * Add trusted proxy IPs.
     *
     * @param array<string> $proxies IPs or CIDR ranges.
     * @return self
     */
    public function withTrustedProxies(array $proxies): self
    {
        $clone = clone $this;
        $clone->trustedProxies = array_merge($clone->trustedProxies, $proxies);
        return $clone;
    }

    /**
     * Set headers to check.
     *
     * @param array<string> $headers Header names in priority order.
     * @return self
     */
    public function withHeaders(array $headers): self
    {
        $clone = clone $this;
        $clone->headers = $headers;
        return $clone;
    }

    /**
     * Trust private/internal networks as proxies.
     *
     * @return self
     */
    public function trustPrivateNetworks(): self
    {
        $clone = clone $this;
        $clone->trustPrivateNetworks = true;
        return $clone;
    }

    // =========================================================================
    // Factory Methods
    // =========================================================================

    /**
     * Create middleware for Cloudflare.
     *
     * Trusts Cloudflare IP ranges and uses CF-Connecting-IP header.
     */
    public static function forCloudflare(): self
    {
        return new self(
            trustedProxies: array_merge(self::CLOUDFLARE_IPS_V4, self::CLOUDFLARE_IPS_V6),
            headers: [
                self::HEADER_CF_CONNECTING_IP,
                self::HEADER_TRUE_CLIENT_IP,
            ],
        );
    }

    /**
     * Create middleware for Nginx reverse proxy.
     *
     * Trusts private networks and uses X-Real-IP / X-Forwarded-For.
     */
    public static function forNginx(): self
    {
        return new self(
            trustedProxies: self::PRIVATE_RANGES,
            headers: [
                self::HEADER_X_REAL_IP,
                self::HEADER_X_FORWARDED_FOR,
            ],
        );
    }

    /**
     * Create middleware for AWS Application Load Balancer.
     *
     * Trusts private networks and uses X-Forwarded-For.
     */
    public static function forAwsAlb(): self
    {
        return new self(
            trustedProxies: self::PRIVATE_RANGES,
            headers: [
                self::HEADER_X_FORWARDED_FOR,
            ],
        );
    }

    /**
     * Create middleware for local development (trust everything).
     *
     * WARNING: Do NOT use in production!
     */
    public static function forDevelopment(): self
    {
        return new self(
            trustedProxies: [],
            headers: [
                self::HEADER_CF_CONNECTING_IP,
                self::HEADER_TRUE_CLIENT_IP,
                self::HEADER_X_REAL_IP,
                self::HEADER_X_FORWARDED_FOR,
                self::HEADER_X_CLIENT_IP,
                self::HEADER_FORWARDED,
            ],
            trustPrivateNetworks: true,
        );
    }

    /**
     * Create middleware from configuration array.
     *
     * @param array{
     *     trusted_proxies?: array<string>,
     *     headers?: array<string>,
     *     trust_private_networks?: bool,
     *     ip_attribute?: string|null,
     * } $config
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            trustedProxies: $config['trusted_proxies'] ?? [],
            headers: $config['headers'] ?? [
                self::HEADER_CF_CONNECTING_IP,
                self::HEADER_TRUE_CLIENT_IP,
                self::HEADER_X_REAL_IP,
                self::HEADER_X_FORWARDED_FOR,
                self::HEADER_X_CLIENT_IP,
                self::HEADER_FORWARDED,
            ],
            trustPrivateNetworks: $config['trust_private_networks'] ?? false,
            ipAttribute: $config['ip_attribute'] ?? 'client_ip',
        );
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    /**
     * Get Cloudflare IPv4 ranges.
     *
     * @return array<string>
     */
    public static function getCloudflareIpsV4(): array
    {
        return self::CLOUDFLARE_IPS_V4;
    }

    /**
     * Get Cloudflare IPv6 ranges.
     *
     * @return array<string>
     */
    public static function getCloudflareIpsV6(): array
    {
        return self::CLOUDFLARE_IPS_V6;
    }

    /**
     * Get all Cloudflare IP ranges.
     *
     * @return array<string>
     */
    public static function getCloudflareIps(): array
    {
        return array_merge(self::CLOUDFLARE_IPS_V4, self::CLOUDFLARE_IPS_V6);
    }

    /**
     * Get private/internal IP ranges.
     *
     * @return array<string>
     */
    public static function getPrivateRanges(): array
    {
        return self::PRIVATE_RANGES;
    }
}
