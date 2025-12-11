<?php

declare(strict_types=1);

namespace Lalaz\Waf;

use Lalaz\Container\ServiceProvider;
use Lalaz\Waf\RateLimit\Contracts\RateLimitStoreInterface;
use Lalaz\Waf\RateLimit\RateLimiter;
use Lalaz\Waf\RateLimit\Stores\CacheStore;
use Lalaz\Waf\RateLimit\Stores\MemoryStore;

/**
 * Service provider for the WAF (Web Application Firewall) package.
 *
 * Registers WAF-related services including:
 * - Rate Limiter
 * - CORS Middleware (configured via config)
 * - Helmet Middleware (configured via config)
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 * @link https://lalaz.dev
 */
final class WafServiceProvider extends ServiceProvider
{
    /**
     * Register WAF services.
     */
    public function register(): void
    {
        $this->registerRateLimiter();
    }

    /**
     * Register the rate limiter and its store.
     */
    private function registerRateLimiter(): void
    {
        // Register the store interface
        $this->singleton(RateLimitStoreInterface::class, function () {
            // Try to use cache if available
            if ($this->container->has('Lalaz\Cache\CacheManager')) {
                $cache = $this->container->get('Lalaz\Cache\CacheManager');
                return new CacheStore($cache, 'rate_limit:');
            }

            // Fall back to memory store (not recommended for production)
            return new MemoryStore();
        });

        // Register the rate limiter
        $this->singleton(RateLimiter::class, function () {
            $store = $this->container->get(RateLimitStoreInterface::class);
            return new RateLimiter($store);
        });
    }
}
