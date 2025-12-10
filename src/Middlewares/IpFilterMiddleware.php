<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Waf\IpFilter\IpList;
use Lalaz\Waf\IpFilter\IpMatcher;
use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * IP Filter Middleware
 *
 * Filters requests based on IP address using whitelist and blacklist.
 * Supports exact IPs, CIDR notation, wildcards, and ranges.
 *
 * Evaluation order:
 * 1. If IP is in whitelist → ALLOW (skip blacklist check)
 * 2. If IP is in blacklist → BLOCK
 * 3. If neither → Use default behavior (allow or deny)
 *
 * @example Basic blacklist:
 * ```php
 * $middleware = IpFilterMiddleware::blacklist([
 *     '192.168.1.100',
 *     '10.0.0.0/8',
 * ]);
 * ```
 *
 * @example Basic whitelist (only these IPs allowed):
 * ```php
 * $middleware = IpFilterMiddleware::whitelist([
 *     '203.0.113.0/24',
 * ]);
 * ```
 *
 * @example Combined whitelist + blacklist:
 * ```php
 * $middleware = IpFilterMiddleware::create()
 *     ->whitelist(['10.0.0.1'])      // Always allow admin
 *     ->blacklist(['10.0.0.0/8'])    // Block internal range
 *     ->denyByDefault();              // Block unknown IPs
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 * @link https://lalaz.dev
 */
class IpFilterMiddleware implements MiddlewareInterface
{
    /**
     * @var IpList Whitelist - IPs that are always allowed.
     */
    private IpList $whitelist;

    /**
     * @var IpList Blacklist - IPs that are always blocked.
     */
    private IpList $blacklist;

    /**
     * @var bool Whether to deny IPs not in any list.
     */
    private bool $denyByDefault;

    /**
     * @var callable|null Custom handler for blocked requests.
     */
    private $onBlockHandler = null;

    /**
     * @var callable|null Custom IP resolver.
     */
    private $ipResolver = null;

    /**
     * @var bool Whether to trust proxy headers.
     */
    private bool $trustProxy;

    /**
     * @var array<string> Trusted proxy IPs.
     */
    private array $trustedProxies;

    /**
     * Create a new IP filter middleware.
     *
     * @param array<string> $whitelist IPs to always allow.
     * @param array<string> $blacklist IPs to always block.
     * @param bool $denyByDefault Deny IPs not in any list.
     * @param bool $trustProxy Trust X-Forwarded-For header.
     * @param array<string> $trustedProxies List of trusted proxy IPs.
     */
    public function __construct(
        array $whitelist = [],
        array $blacklist = [],
        bool $denyByDefault = false,
        bool $trustProxy = false,
        array $trustedProxies = [],
    ) {
        $this->whitelist = new IpList('whitelist', $whitelist);
        $this->blacklist = new IpList('blacklist', $blacklist);
        $this->denyByDefault = $denyByDefault;
        $this->trustProxy = $trustProxy;
        $this->trustedProxies = $trustedProxies;
    }

    /**
     * Handle the incoming request.
     */
    public function handle(RequestInterface $req, ResponseInterface $res, callable $next): mixed
    {
        $ip = $this->resolveIp($req);

        // Check whitelist first (always allow)
        if ($this->whitelist->contains($ip)) {
            return $next($req, $res);
        }

        // Check blacklist
        if ($this->blacklist->contains($ip)) {
            $this->handleBlocked($req, $res, $ip, 'blacklisted');
            return null;
        }

        // If deny by default and not whitelisted
        if ($this->denyByDefault) {
            $this->handleBlocked($req, $res, $ip, 'not_whitelisted');
            return null;
        }

        // Allow the request
        return $next($req, $res);
    }

    /**
     * Resolve the client IP address.
     */
    private function resolveIp(RequestInterface $req): string
    {
        // Use custom resolver if set
        if ($this->ipResolver !== null) {
            return ($this->ipResolver)($req);
        }

        // Get direct IP
        $directIp = $req->ip() ?? '0.0.0.0';

        // Check proxy headers if enabled
        if ($this->trustProxy) {
            // Verify the direct IP is from a trusted proxy
            if (!empty($this->trustedProxies) && !IpMatcher::matchesAny($directIp, $this->trustedProxies)) {
                return $directIp;
            }

            // Try X-Forwarded-For
            $forwarded = $req->header('X-Forwarded-For');
            if ($forwarded !== null && $forwarded !== '') {
                $ips = array_map('trim', explode(',', $forwarded));
                // Get the leftmost IP (original client)
                return $ips[0];
            }

            // Try X-Real-IP
            $realIp = $req->header('X-Real-IP');
            if ($realIp !== null && $realIp !== '') {
                return trim($realIp);
            }
        }

        return $directIp;
    }

    /**
     * Handle a blocked request.
     */
    private function handleBlocked(RequestInterface $req, ResponseInterface $res, string $ip, string $reason): void
    {
        if ($this->onBlockHandler !== null) {
            ($this->onBlockHandler)($req, $res, $ip, $reason);
            return;
        }

        $res->json([
            'error' => 'Forbidden',
            'message' => 'Access denied',
        ], 403);
    }

    /**
     * Add IPs to the whitelist.
     *
     * @param array<string> $ips IPs to whitelist.
     * @return self
     */
    public function allow(array $ips): self
    {
        $this->whitelist->addMany($ips);
        return $this;
    }

    /**
     * Add IPs to the blacklist.
     *
     * @param array<string> $ips IPs to blacklist.
     * @return self
     */
    public function block(array $ips): self
    {
        $this->blacklist->addMany($ips);
        return $this;
    }

    /**
     * Remove IPs from the whitelist.
     *
     * @param array<string> $ips IPs to remove.
     * @return self
     */
    public function removeFromWhitelist(array $ips): self
    {
        $this->whitelist->removeMany($ips);
        return $this;
    }

    /**
     * Remove IPs from the blacklist.
     *
     * @param array<string> $ips IPs to remove.
     * @return self
     */
    public function removeFromBlacklist(array $ips): self
    {
        $this->blacklist->removeMany($ips);
        return $this;
    }

    /**
     * Set deny by default behavior.
     *
     * @param bool $deny Whether to deny by default.
     * @return self
     */
    public function denyByDefault(bool $deny = true): self
    {
        $this->denyByDefault = $deny;
        return $this;
    }

    /**
     * Set allow by default behavior.
     *
     * @return self
     */
    public function allowByDefault(): self
    {
        $this->denyByDefault = false;
        return $this;
    }

    /**
     * Set a custom handler for blocked requests.
     *
     * @param callable $handler Function that receives (RequestInterface, ResponseInterface, string $ip, string $reason).
     * @return self
     */
    public function onBlock(callable $handler): self
    {
        $this->onBlockHandler = $handler;
        return $this;
    }

    /**
     * Set a custom IP resolver.
     *
     * @param callable $resolver Function that receives (RequestInterface) and returns string.
     * @return self
     */
    public function resolveIpWith(callable $resolver): self
    {
        $this->ipResolver = $resolver;
        return $this;
    }

    /**
     * Enable trusting proxy headers.
     *
     * @param array<string> $trustedProxies Trusted proxy IPs (empty = trust all).
     * @return self
     */
    public function trustProxy(array $trustedProxies = []): self
    {
        $this->trustProxy = true;
        $this->trustedProxies = $trustedProxies;
        return $this;
    }

    /**
     * Get the whitelist.
     *
     * @return IpList
     */
    public function getWhitelist(): IpList
    {
        return $this->whitelist;
    }

    /**
     * Get the blacklist.
     *
     * @return IpList
     */
    public function getBlacklist(): IpList
    {
        return $this->blacklist;
    }

    /**
     * Check if an IP would be allowed.
     *
     * @param string $ip The IP to check.
     * @return bool True if the IP would be allowed.
     */
    public function wouldAllow(string $ip): bool
    {
        // Whitelisted = always allowed
        if ($this->whitelist->contains($ip)) {
            return true;
        }

        // Blacklisted = always blocked
        if ($this->blacklist->contains($ip)) {
            return false;
        }

        // Default behavior
        return !$this->denyByDefault;
    }

    /**
     * Create a new middleware instance.
     *
     * @return self
     */
    public static function create(): self
    {
        return new self();
    }

    /**
     * Create a whitelist-only middleware (deny by default).
     *
     * @param array<string> $ips Allowed IPs.
     * @return self
     */
    public static function whitelist(array $ips): self
    {
        return new self(
            whitelist: $ips,
            blacklist: [],
            denyByDefault: true,
        );
    }

    /**
     * Create a blacklist-only middleware (allow by default).
     *
     * @param array<string> $ips Blocked IPs.
     * @return self
     */
    public static function blacklist(array $ips): self
    {
        return new self(
            whitelist: [],
            blacklist: $ips,
            denyByDefault: false,
        );
    }

    /**
     * Create middleware from configuration array.
     *
     * @param array<string, mixed> $config Configuration options.
     * @return self
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            whitelist: $config['whitelist'] ?? [],
            blacklist: $config['blacklist'] ?? [],
            denyByDefault: $config['deny_by_default'] ?? false,
            trustProxy: $config['trust_proxy'] ?? false,
            trustedProxies: $config['trusted_proxies'] ?? [],
        );
    }

    /**
     * Create middleware from files.
     *
     * @param string|null $whitelistFile Path to whitelist file.
     * @param string|null $blacklistFile Path to blacklist file.
     * @param bool $denyByDefault Deny by default behavior.
     * @return self
     */
    public static function fromFiles(
        ?string $whitelistFile = null,
        ?string $blacklistFile = null,
        bool $denyByDefault = false,
    ): self {
        $whitelist = $whitelistFile !== null
            ? IpList::fromFile($whitelistFile, 'whitelist')->all()
            : [];

        $blacklist = $blacklistFile !== null
            ? IpList::fromFile($blacklistFile, 'blacklist')->all()
            : [];

        return new self(
            whitelist: $whitelist,
            blacklist: $blacklist,
            denyByDefault: $denyByDefault,
        );
    }

    /**
     * Create middleware that blocks private/internal IPs.
     *
     * @return self
     */
    public static function blockPrivate(): self
    {
        return self::blacklist([
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '::1/128',
            'fc00::/7',
            'fe80::/10',
        ]);
    }

    /**
     * Create middleware that only allows private/internal IPs.
     *
     * @return self
     */
    public static function allowPrivateOnly(): self
    {
        return self::whitelist([
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '::1/128',
            'fc00::/7',
        ]);
    }

    /**
     * Create middleware for internal APIs (localhost + private ranges).
     *
     * @return self
     */
    public static function internalOnly(): self
    {
        return self::whitelist([
            '127.0.0.1',
            '::1',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ]);
    }
}
