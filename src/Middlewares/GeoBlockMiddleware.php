<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Waf\Geo\Contracts\GeoProviderInterface;
use Lalaz\Waf\Geo\GeoLocation;
use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * Geo Blocking Middleware
 *
 * Blocks or allows requests based on geographic location determined by IP address.
 * Requires a GeoIP provider to resolve IP addresses to countries.
 *
 * @example Allow only specific countries:
 * ```php
 * $middleware = GeoBlockMiddleware::allowOnly(['US', 'CA', 'BR'], $geoProvider);
 * ```
 *
 * @example Block specific countries:
 * ```php
 * $middleware = GeoBlockMiddleware::blockOnly(['CN', 'RU', 'KP'], $geoProvider);
 * ```
 *
 * @example Block anonymized IPs (VPN, Proxy, Tor):
 * ```php
 * $middleware = (new GeoBlockMiddleware($geoProvider))
 *     ->blockAnonymized();
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 * @link https://lalaz.dev
 */
class GeoBlockMiddleware implements MiddlewareInterface
{
    /**
     * @var array<string> List of allowed country codes (whitelist).
     */
    private array $allowedCountries = [];

    /**
     * @var array<string> List of blocked country codes (blacklist).
     */
    private array $blockedCountries = [];

    /**
     * @var array<string> List of allowed continent codes.
     */
    private array $allowedContinents = [];

    /**
     * @var array<string> List of blocked continent codes.
     */
    private array $blockedContinents = [];

    /**
     * @var bool Whether to block requests when country cannot be determined.
     */
    private bool $blockUnknown = false;

    /**
     * @var bool Whether to block anonymized IPs (VPN, Proxy, Tor).
     */
    private bool $blockAnonymized = false;

    /**
     * @var bool Whether to block hosting/datacenter IPs.
     */
    private bool $blockHosting = false;

    /**
     * @var callable|null Custom IP resolver.
     */
    private $ipResolver = null;

    /**
     * @var callable|null Custom handler for blocked requests.
     */
    private $onBlockHandler = null;

    /**
     * @var callable|null Callback when a request is checked.
     */
    private $onCheckHandler = null;

    /**
     * @var array<string> List of IPs to always allow (bypass geo check).
     */
    private array $whitelistedIps = [];

    /**
     * @var bool Whether to trust proxy headers for IP detection.
     */
    private bool $trustProxy = false;

    /**
     * Create a new geo blocking middleware.
     *
     * @param GeoProviderInterface $geoProvider The geo IP provider.
     */
    public function __construct(
        private readonly GeoProviderInterface $geoProvider,
    ) {
    }

    /**
     * Handle the incoming request.
     */
    public function handle(RequestInterface $req, ResponseInterface $res, callable $next): mixed
    {
        $ip = $this->resolveIp($req);

        // Check IP whitelist first
        if ($this->isIpWhitelisted($ip)) {
            return $next($req, $res);
        }

        // Lookup geo information
        $location = $this->geoProvider->lookup($ip);

        // Call check handler if set
        if ($this->onCheckHandler !== null) {
            ($this->onCheckHandler)($ip, $location, $req);
        }

        // Check if blocked
        $blockReason = $this->getBlockReason($location);

        if ($blockReason !== null) {
            $this->handleBlocked($req, $res, $ip, $location, $blockReason);
            return null;
        }

        return $next($req, $res);
    }

    /**
     * Get the reason for blocking, or null if allowed.
     *
     * @param GeoLocation|null $location
     * @return string|null Block reason or null if allowed.
     */
    private function getBlockReason(?GeoLocation $location): ?string
    {
        // Unknown location handling
        if ($location === null || $location->countryCode === null) {
            if ($this->blockUnknown) {
                return 'unknown_location';
            }
            // If we have an allowlist and unknown, block
            if (!empty($this->allowedCountries) || !empty($this->allowedContinents)) {
                return 'not_in_allowlist';
            }
            return null;
        }

        $countryCode = strtoupper($location->countryCode);
        $continentCode = $location->continent ? strtoupper($location->continent) : null;

        // Check anonymized IPs
        if ($this->blockAnonymized && $location->isAnonymized()) {
            return 'anonymized_ip';
        }

        // Check hosting/datacenter IPs
        if ($this->blockHosting && $location->isHosting === true) {
            return 'hosting_ip';
        }

        // Check continent blocklist
        if ($continentCode !== null && !empty($this->blockedContinents)) {
            if (in_array($continentCode, $this->blockedContinents, true)) {
                return 'blocked_continent';
            }
        }

        // Check country blocklist
        if (!empty($this->blockedCountries)) {
            if (in_array($countryCode, $this->blockedCountries, true)) {
                return 'blocked_country';
            }
        }

        // Check continent allowlist
        if (!empty($this->allowedContinents)) {
            if ($continentCode === null || !in_array($continentCode, $this->allowedContinents, true)) {
                return 'not_in_allowed_continent';
            }
        }

        // Check country allowlist
        if (!empty($this->allowedCountries)) {
            if (!in_array($countryCode, $this->allowedCountries, true)) {
                return 'not_in_allowed_country';
            }
        }

        return null;
    }

    /**
     * Handle a blocked request.
     */
    private function handleBlocked(
        RequestInterface $req,
        ResponseInterface $res,
        string $ip,
        ?GeoLocation $location,
        string $reason,
    ): void {
        if ($this->onBlockHandler !== null) {
            ($this->onBlockHandler)($req, $res, $ip, $location, $reason);
            return;
        }

        $countryCode = $location?->countryCode ?? 'Unknown';

        $res->json([
            'error' => 'Access Denied',
            'message' => "Access from your location ({$countryCode}) is not allowed.",
            'reason' => $reason,
        ], 403);
    }

    /**
     * Resolve the client IP address.
     */
    private function resolveIp(RequestInterface $req): string
    {
        if ($this->ipResolver !== null) {
            return ($this->ipResolver)($req);
        }

        if ($this->trustProxy) {
            $forwardedFor = $req->header('X-Forwarded-For');
            if ($forwardedFor !== null) {
                $ips = array_map('trim', explode(',', $forwardedFor));
                return $ips[0];
            }

            $realIp = $req->header('X-Real-IP');
            if ($realIp !== null) {
                return $realIp;
            }
        }

        return $req->ip();
    }

    /**
     * Check if an IP is in the whitelist.
     */
    private function isIpWhitelisted(string $ip): bool
    {
        return in_array($ip, $this->whitelistedIps, true);
    }

    // ========================================
    // Configuration Methods
    // ========================================

    /**
     * Set allowed countries (whitelist mode).
     *
     * @param array<string> $countryCodes ISO 3166-1 alpha-2 country codes.
     * @return self
     */
    public function allowCountries(array $countryCodes): self
    {
        $this->allowedCountries = array_map('strtoupper', $countryCodes);
        return $this;
    }

    /**
     * Set blocked countries (blacklist mode).
     *
     * @param array<string> $countryCodes ISO 3166-1 alpha-2 country codes.
     * @return self
     */
    public function blockCountries(array $countryCodes): self
    {
        $this->blockedCountries = array_map('strtoupper', $countryCodes);
        return $this;
    }

    /**
     * Set allowed continents.
     *
     * @param array<string> $continentCodes Continent codes (AF, AN, AS, EU, NA, OC, SA).
     * @return self
     */
    public function allowContinents(array $continentCodes): self
    {
        $this->allowedContinents = array_map('strtoupper', $continentCodes);
        return $this;
    }

    /**
     * Set blocked continents.
     *
     * @param array<string> $continentCodes Continent codes (AF, AN, AS, EU, NA, OC, SA).
     * @return self
     */
    public function blockContinents(array $continentCodes): self
    {
        $this->blockedContinents = array_map('strtoupper', $continentCodes);
        return $this;
    }

    /**
     * Block requests when country cannot be determined.
     *
     * @param bool $block
     * @return self
     */
    public function blockUnknown(bool $block = true): self
    {
        $this->blockUnknown = $block;
        return $this;
    }

    /**
     * Block anonymized IPs (VPN, Proxy, Tor).
     *
     * @param bool $block
     * @return self
     */
    public function blockAnonymized(bool $block = true): self
    {
        $this->blockAnonymized = $block;
        return $this;
    }

    /**
     * Block hosting/datacenter IPs.
     *
     * @param bool $block
     * @return self
     */
    public function blockHosting(bool $block = true): self
    {
        $this->blockHosting = $block;
        return $this;
    }

    /**
     * Set IPs that bypass geo checking.
     *
     * @param array<string> $ips
     * @return self
     */
    public function whitelistIps(array $ips): self
    {
        $this->whitelistedIps = $ips;
        return $this;
    }

    /**
     * Trust proxy headers for IP detection.
     *
     * @param bool $trust
     * @return self
     */
    public function trustProxy(bool $trust = true): self
    {
        $this->trustProxy = $trust;
        return $this;
    }

    /**
     * Set custom IP resolver.
     *
     * @param callable $resolver Function(RequestInterface): string
     * @return self
     */
    public function setIpResolver(callable $resolver): self
    {
        $this->ipResolver = $resolver;
        return $this;
    }

    /**
     * Set custom handler for blocked requests.
     *
     * @param callable $handler Function(RequestInterface, ResponseInterface, string $ip, ?GeoLocation, string $reason)
     * @return self
     */
    public function onBlock(callable $handler): self
    {
        $this->onBlockHandler = $handler;
        return $this;
    }

    /**
     * Set callback for when a request is checked.
     *
     * @param callable $handler Function(string $ip, ?GeoLocation, RequestInterface)
     * @return self
     */
    public function onCheck(callable $handler): self
    {
        $this->onCheckHandler = $handler;
        return $this;
    }

    // ========================================
    // Getters
    // ========================================

    /**
     * Get the list of allowed countries.
     *
     * @return array<string>
     */
    public function getAllowedCountries(): array
    {
        return $this->allowedCountries;
    }

    /**
     * Get the list of blocked countries.
     *
     * @return array<string>
     */
    public function getBlockedCountries(): array
    {
        return $this->blockedCountries;
    }

    /**
     * Get the geo provider.
     *
     * @return GeoProviderInterface
     */
    public function getGeoProvider(): GeoProviderInterface
    {
        return $this->geoProvider;
    }

    /**
     * Check if a country would be allowed.
     *
     * @param string $countryCode ISO 3166-1 alpha-2 country code.
     * @return bool
     */
    public function wouldAllowCountry(string $countryCode): bool
    {
        $location = GeoLocation::forCountry($countryCode);
        return $this->getBlockReason($location) === null;
    }

    // ========================================
    // Factory Methods
    // ========================================

    /**
     * Create a middleware that allows only specific countries.
     *
     * @param array<string> $countryCodes ISO 3166-1 alpha-2 country codes.
     * @param GeoProviderInterface $geoProvider The geo IP provider.
     * @return self
     */
    public static function allowOnly(array $countryCodes, GeoProviderInterface $geoProvider): self
    {
        return (new self($geoProvider))
            ->allowCountries($countryCodes);
    }

    /**
     * Create a middleware that blocks specific countries.
     *
     * @param array<string> $countryCodes ISO 3166-1 alpha-2 country codes.
     * @param GeoProviderInterface $geoProvider The geo IP provider.
     * @return self
     */
    public static function blockOnly(array $countryCodes, GeoProviderInterface $geoProvider): self
    {
        return (new self($geoProvider))
            ->blockCountries($countryCodes);
    }

    /**
     * Create a strict middleware that blocks anonymous IPs and unknown locations.
     *
     * @param array<string> $allowedCountries ISO 3166-1 alpha-2 country codes.
     * @param GeoProviderInterface $geoProvider The geo IP provider.
     * @return self
     */
    public static function strict(array $allowedCountries, GeoProviderInterface $geoProvider): self
    {
        return (new self($geoProvider))
            ->allowCountries($allowedCountries)
            ->blockUnknown(true)
            ->blockAnonymized(true)
            ->blockHosting(true);
    }

    /**
     * Create middleware from configuration array.
     *
     * @param array<string, mixed> $config
     * @param GeoProviderInterface $geoProvider
     * @return self
     */
    public static function fromConfig(array $config, GeoProviderInterface $geoProvider): self
    {
        $middleware = new self($geoProvider);

        if (isset($config['allowed_countries'])) {
            $middleware->allowCountries($config['allowed_countries']);
        }

        if (isset($config['blocked_countries'])) {
            $middleware->blockCountries($config['blocked_countries']);
        }

        if (isset($config['allowed_continents'])) {
            $middleware->allowContinents($config['allowed_continents']);
        }

        if (isset($config['blocked_continents'])) {
            $middleware->blockContinents($config['blocked_continents']);
        }

        if (isset($config['block_unknown'])) {
            $middleware->blockUnknown((bool) $config['block_unknown']);
        }

        if (isset($config['block_anonymized'])) {
            $middleware->blockAnonymized((bool) $config['block_anonymized']);
        }

        if (isset($config['block_hosting'])) {
            $middleware->blockHosting((bool) $config['block_hosting']);
        }

        if (isset($config['whitelisted_ips'])) {
            $middleware->whitelistIps($config['whitelisted_ips']);
        }

        if (isset($config['trust_proxy'])) {
            $middleware->trustProxy((bool) $config['trust_proxy']);
        }

        return $middleware;
    }
}
