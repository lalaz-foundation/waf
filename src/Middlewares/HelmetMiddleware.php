<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * Security Headers Middleware (Helmet)
 *
 * Adds security-related HTTP headers to protect against common web vulnerabilities.
 * Inspired by the Express.js Helmet middleware.
 *
 * Headers included:
 * - Content-Security-Policy (CSP) - Prevents XSS and data injection
 * - X-Content-Type-Options - Prevents MIME sniffing
 * - X-Frame-Options - Prevents clickjacking
 * - X-XSS-Protection - Legacy XSS protection for older browsers
 * - Referrer-Policy - Controls referrer information
 * - Strict-Transport-Security (HSTS) - Forces HTTPS
 * - Permissions-Policy - Controls browser features
 *
 * @example Basic usage with defaults:
 * ```php
 * $router->middleware(new HelmetMiddleware());
 * ```
 *
 * @example Custom configuration:
 * ```php
 * $router->middleware(HelmetMiddleware::fromConfig([
 *     'content_security_policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'",
 *     'hsts' => ['max_age' => 31536000, 'include_subdomains' => true],
 *     'frame_options' => 'SAMEORIGIN',
 * ]));
 * ```
 *
 * @example Strict mode for maximum security:
 * ```php
 * $router->middleware(HelmetMiddleware::strict());
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 * @link https://lalaz.dev
 */
class HelmetMiddleware implements MiddlewareInterface
{
    /**
     * @var string|null Content Security Policy directive
     */
    private ?string $contentSecurityPolicy;

    /**
     * @var bool Whether to add X-Content-Type-Options header
     */
    private bool $noSniff;

    /**
     * @var string|null X-Frame-Options value (DENY, SAMEORIGIN, or null to disable)
     */
    private ?string $frameOptions;

    /**
     * @var bool Whether to add X-XSS-Protection header
     */
    private bool $xssProtection;

    /**
     * @var string|null Referrer-Policy value
     */
    private ?string $referrerPolicy;

    /**
     * @var array{max_age: int, include_subdomains: bool, preload: bool}|null HSTS configuration
     */
    private ?array $hsts;

    /**
     * @var string|null Permissions-Policy value
     */
    private ?string $permissionsPolicy;

    /**
     * @var bool Whether to remove X-Powered-By header
     */
    private bool $hidePoweredBy;

    /**
     * @var string|null Cross-Origin-Embedder-Policy value
     */
    private ?string $crossOriginEmbedderPolicy;

    /**
     * @var string|null Cross-Origin-Opener-Policy value
     */
    private ?string $crossOriginOpenerPolicy;

    /**
     * @var string|null Cross-Origin-Resource-Policy value
     */
    private ?string $crossOriginResourcePolicy;

    /**
     * Create a new Helmet middleware instance.
     *
     * @param string|null $contentSecurityPolicy CSP directive string
     * @param bool $noSniff Add X-Content-Type-Options: nosniff
     * @param string|null $frameOptions DENY, SAMEORIGIN, or null
     * @param bool $xssProtection Add X-XSS-Protection header
     * @param string|null $referrerPolicy Referrer policy value
     * @param array{max_age?: int, include_subdomains?: bool, preload?: bool}|null $hsts HSTS config
     * @param string|null $permissionsPolicy Permissions policy string
     * @param bool $hidePoweredBy Remove X-Powered-By header
     * @param string|null $crossOriginEmbedderPolicy COEP value
     * @param string|null $crossOriginOpenerPolicy COOP value
     * @param string|null $crossOriginResourcePolicy CORP value
     */
    public function __construct(
        ?string $contentSecurityPolicy = "default-src 'self'",
        bool $noSniff = true,
        ?string $frameOptions = 'SAMEORIGIN',
        bool $xssProtection = true,
        ?string $referrerPolicy = 'strict-origin-when-cross-origin',
        ?array $hsts = ['max_age' => 31536000, 'include_subdomains' => true, 'preload' => false],
        ?string $permissionsPolicy = null,
        bool $hidePoweredBy = true,
        ?string $crossOriginEmbedderPolicy = null,
        ?string $crossOriginOpenerPolicy = 'same-origin',
        ?string $crossOriginResourcePolicy = 'same-origin',
    ) {
        $this->contentSecurityPolicy = $contentSecurityPolicy;
        $this->noSniff = $noSniff;
        $this->frameOptions = $frameOptions;
        $this->xssProtection = $xssProtection;
        $this->referrerPolicy = $referrerPolicy;
        $this->hsts = $hsts;
        $this->permissionsPolicy = $permissionsPolicy;
        $this->hidePoweredBy = $hidePoweredBy;
        $this->crossOriginEmbedderPolicy = $crossOriginEmbedderPolicy;
        $this->crossOriginOpenerPolicy = $crossOriginOpenerPolicy;
        $this->crossOriginResourcePolicy = $crossOriginResourcePolicy;
    }

    /**
     * Handle the incoming request.
     */
    public function handle(RequestInterface $req, ResponseInterface $res, callable $next): mixed
    {
        // Add security headers before processing
        $this->addSecurityHeaders($res);

        // Continue with the request
        return $next($req, $res);
    }

    /**
     * Add all configured security headers to the response.
     */
    private function addSecurityHeaders(ResponseInterface $res): void
    {
        // Content Security Policy
        if ($this->contentSecurityPolicy !== null) {
            $res->header('Content-Security-Policy', $this->contentSecurityPolicy);
        }

        // X-Content-Type-Options
        if ($this->noSniff) {
            $res->header('X-Content-Type-Options', 'nosniff');
        }

        // X-Frame-Options
        if ($this->frameOptions !== null) {
            $res->header('X-Frame-Options', $this->frameOptions);
        }

        // X-XSS-Protection (legacy, but still useful for older browsers)
        if ($this->xssProtection) {
            $res->header('X-XSS-Protection', '1; mode=block');
        }

        // Referrer-Policy
        if ($this->referrerPolicy !== null) {
            $res->header('Referrer-Policy', $this->referrerPolicy);
        }

        // Strict-Transport-Security (HSTS)
        if ($this->hsts !== null) {
            $res->header('Strict-Transport-Security', $this->buildHstsHeader());
        }

        // Permissions-Policy
        if ($this->permissionsPolicy !== null) {
            $res->header('Permissions-Policy', $this->permissionsPolicy);
        }

        // Cross-Origin-Embedder-Policy
        if ($this->crossOriginEmbedderPolicy !== null) {
            $res->header('Cross-Origin-Embedder-Policy', $this->crossOriginEmbedderPolicy);
        }

        // Cross-Origin-Opener-Policy
        if ($this->crossOriginOpenerPolicy !== null) {
            $res->header('Cross-Origin-Opener-Policy', $this->crossOriginOpenerPolicy);
        }

        // Cross-Origin-Resource-Policy
        if ($this->crossOriginResourcePolicy !== null) {
            $res->header('Cross-Origin-Resource-Policy', $this->crossOriginResourcePolicy);
        }

        // Remove X-Powered-By (handled at PHP level, but we add a note)
        if ($this->hidePoweredBy) {
            // Can't remove headers in standard response, but we can override
            // This is typically handled by PHP ini or web server config
            $res->header('X-Powered-By', '');
        }
    }

    /**
     * Build the HSTS header value.
     */
    private function buildHstsHeader(): string
    {
        $value = 'max-age=' . ($this->hsts['max_age'] ?? 31536000);

        if ($this->hsts['include_subdomains'] ?? false) {
            $value .= '; includeSubDomains';
        }

        if ($this->hsts['preload'] ?? false) {
            $value .= '; preload';
        }

        return $value;
    }

    /**
     * Create middleware instance from configuration array.
     *
     * @param array<string, mixed> $config Configuration options
     * @return self
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            contentSecurityPolicy: $config['content_security_policy'] ?? "default-src 'self'",
            noSniff: $config['no_sniff'] ?? true,
            frameOptions: $config['frame_options'] ?? 'SAMEORIGIN',
            xssProtection: $config['xss_protection'] ?? true,
            referrerPolicy: $config['referrer_policy'] ?? 'strict-origin-when-cross-origin',
            hsts: $config['hsts'] ?? ['max_age' => 31536000, 'include_subdomains' => true, 'preload' => false],
            permissionsPolicy: $config['permissions_policy'] ?? null,
            hidePoweredBy: $config['hide_powered_by'] ?? true,
            crossOriginEmbedderPolicy: $config['cross_origin_embedder_policy'] ?? null,
            crossOriginOpenerPolicy: $config['cross_origin_opener_policy'] ?? 'same-origin',
            crossOriginResourcePolicy: $config['cross_origin_resource_policy'] ?? 'same-origin',
        );
    }

    /**
     * Create a strict Helmet middleware with maximum security.
     * Suitable for production environments with high security requirements.
     *
     * @return self
     */
    public static function strict(): self
    {
        return new self(
            contentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            noSniff: true,
            frameOptions: 'DENY',
            xssProtection: true,
            referrerPolicy: 'strict-origin-when-cross-origin',
            hsts: ['max_age' => 31536000, 'include_subdomains' => true, 'preload' => true],
            permissionsPolicy: 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
            hidePoweredBy: true,
            crossOriginEmbedderPolicy: 'require-corp',
            crossOriginOpenerPolicy: 'same-origin',
            crossOriginResourcePolicy: 'same-origin',
        );
    }

    /**
     * Create a relaxed Helmet middleware for development.
     * Less restrictive but still provides basic security headers.
     *
     * @return self
     */
    public static function development(): self
    {
        return new self(
            contentSecurityPolicy: null, // Disabled for easier debugging
            noSniff: true,
            frameOptions: 'SAMEORIGIN',
            xssProtection: true,
            referrerPolicy: 'no-referrer-when-downgrade',
            hsts: null, // Disabled for HTTP development
            permissionsPolicy: null,
            hidePoweredBy: false,
            crossOriginEmbedderPolicy: null,
            crossOriginOpenerPolicy: null,
            crossOriginResourcePolicy: null,
        );
    }

    /**
     * Create an API-focused Helmet middleware.
     * Optimized for JSON API responses.
     *
     * @return self
     */
    public static function api(): self
    {
        return new self(
            contentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'",
            noSniff: true,
            frameOptions: 'DENY',
            xssProtection: false, // Not needed for JSON APIs
            referrerPolicy: 'no-referrer',
            hsts: ['max_age' => 31536000, 'include_subdomains' => true, 'preload' => false],
            permissionsPolicy: 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
            hidePoweredBy: true,
            crossOriginEmbedderPolicy: null,
            crossOriginOpenerPolicy: 'same-origin',
            crossOriginResourcePolicy: 'same-origin',
        );
    }

    /**
     * Build a custom CSP directive using a fluent builder.
     *
     * @return CspBuilder
     */
    public static function csp(): CspBuilder
    {
        return new CspBuilder();
    }
}

/**
 * Fluent builder for Content Security Policy directives.
 */
class CspBuilder
{
    /** @var array<string, array<string>> */
    private array $directives = [];

    /**
     * Set the default-src directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function defaultSrc(string ...$sources): self
    {
        $this->directives['default-src'] = $sources;
        return $this;
    }

    /**
     * Set the script-src directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function scriptSrc(string ...$sources): self
    {
        $this->directives['script-src'] = $sources;
        return $this;
    }

    /**
     * Set the style-src directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function styleSrc(string ...$sources): self
    {
        $this->directives['style-src'] = $sources;
        return $this;
    }

    /**
     * Set the img-src directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function imgSrc(string ...$sources): self
    {
        $this->directives['img-src'] = $sources;
        return $this;
    }

    /**
     * Set the font-src directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function fontSrc(string ...$sources): self
    {
        $this->directives['font-src'] = $sources;
        return $this;
    }

    /**
     * Set the connect-src directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function connectSrc(string ...$sources): self
    {
        $this->directives['connect-src'] = $sources;
        return $this;
    }

    /**
     * Set the frame-src directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function frameSrc(string ...$sources): self
    {
        $this->directives['frame-src'] = $sources;
        return $this;
    }

    /**
     * Set the frame-ancestors directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function frameAncestors(string ...$sources): self
    {
        $this->directives['frame-ancestors'] = $sources;
        return $this;
    }

    /**
     * Set the object-src directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function objectSrc(string ...$sources): self
    {
        $this->directives['object-src'] = $sources;
        return $this;
    }

    /**
     * Set the base-uri directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function baseUri(string ...$sources): self
    {
        $this->directives['base-uri'] = $sources;
        return $this;
    }

    /**
     * Set the form-action directive.
     *
     * @param string ...$sources
     * @return self
     */
    public function formAction(string ...$sources): self
    {
        $this->directives['form-action'] = $sources;
        return $this;
    }

    /**
     * Set the report-uri directive.
     *
     * @param string $uri
     * @return self
     */
    public function reportUri(string $uri): self
    {
        $this->directives['report-uri'] = [$uri];
        return $this;
    }

    /**
     * Add upgrade-insecure-requests directive.
     *
     * @return self
     */
    public function upgradeInsecureRequests(): self
    {
        $this->directives['upgrade-insecure-requests'] = [];
        return $this;
    }

    /**
     * Add block-all-mixed-content directive.
     *
     * @return self
     */
    public function blockAllMixedContent(): self
    {
        $this->directives['block-all-mixed-content'] = [];
        return $this;
    }

    /**
     * Build the CSP directive string.
     *
     * @return string
     */
    public function build(): string
    {
        $parts = [];

        foreach ($this->directives as $directive => $sources) {
            if (empty($sources)) {
                $parts[] = $directive;
            } else {
                $parts[] = $directive . ' ' . implode(' ', $sources);
            }
        }

        return implode('; ', $parts);
    }

    /**
     * Convert to string.
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->build();
    }
}
