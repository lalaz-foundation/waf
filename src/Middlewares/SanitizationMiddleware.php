<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Waf\Detection\Threat;
use Lalaz\Waf\Detection\ThreatDetector;
use Lalaz\Waf\Detection\ThreatType;
use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * Sanitization Middleware
 *
 * Detects and blocks malicious payloads in request data including
 * XSS, SQL Injection, Path Traversal, and Command Injection.
 *
 * @example Basic usage:
 * ```php
 * $middleware = new SanitizationMiddleware();
 * ```
 *
 * @example Strict mode with logging:
 * ```php
 * $middleware = SanitizationMiddleware::strict()
 *     ->onThreat(function($request, $threats) {
 *         foreach ($threats as $threat) {
 *             logger()->warning('Threat detected', $threat->toArray());
 *         }
 *     });
 * ```
 *
 * @example Log only mode:
 * ```php
 * $middleware = SanitizationMiddleware::logOnly()
 *     ->onThreat(function($request, $threats) {
 *         // Log but don't block
 *     });
 * ```
 *
 * @package lalaz/waf
 */
class SanitizationMiddleware implements MiddlewareInterface
{
    /**
     * @var ThreatDetector The threat detector instance.
     */
    private ThreatDetector $detector;

    /**
     * @var bool Whether to only log threats (not block).
     */
    private bool $logOnly;

    /**
     * @var bool Whether to scan URL path.
     */
    private bool $scanPath;

    /**
     * @var bool Whether to scan query parameters.
     */
    private bool $scanQuery;

    /**
     * @var bool Whether to scan request body.
     */
    private bool $scanBody;

    /**
     * @var bool Whether to scan headers.
     */
    private bool $scanHeaders;

    /**
     * @var bool Whether to scan cookies.
     */
    private bool $scanCookies;

    /**
     * @var callable|null Handler called when threats are detected.
     */
    private $onThreatHandler = null;

    /**
     * @var callable|null Custom blocked response handler.
     */
    private $onBlockHandler = null;

    /**
     * @var array<string> Headers to exclude from scanning.
     */
    private array $excludedHeaders = [
        'Authorization',
        'Cookie',
        'Accept',
        'Accept-Language',
        'Accept-Encoding',
        'Connection',
        'Host',
        'User-Agent',
        'Cache-Control',
        'Content-Type',
        'Content-Length',
    ];

    /**
     * @var array<ThreatType> Threat types to block (null = all).
     */
    private ?array $blockTypes = null;

    /**
     * Create a new sanitization middleware.
     *
     * @param bool $detectXss Enable XSS detection.
     * @param bool $detectSqlInjection Enable SQL injection detection.
     * @param bool $detectPathTraversal Enable path traversal detection.
     * @param bool $detectCommandInjection Enable command injection detection.
     * @param bool $logOnly Only log threats, don't block.
     */
    public function __construct(
        bool $detectXss = true,
        bool $detectSqlInjection = true,
        bool $detectPathTraversal = true,
        bool $detectCommandInjection = false,
        bool $logOnly = false,
    ) {
        $this->detector = new ThreatDetector(
            detectXss: $detectXss,
            detectSqlInjection: $detectSqlInjection,
            detectPathTraversal: $detectPathTraversal,
            detectCommandInjection: $detectCommandInjection,
        );

        $this->logOnly = $logOnly;
        $this->scanPath = true;
        $this->scanQuery = true;
        $this->scanBody = true;
        $this->scanHeaders = false;
        $this->scanCookies = false;
    }

    /**
     * Handle the incoming request.
     */
    public function handle(RequestInterface $req, ResponseInterface $res, callable $next): mixed
    {
        $threats = $this->detectThreats($req);

        if (!empty($threats)) {
            // Call threat handler
            if ($this->onThreatHandler !== null) {
                ($this->onThreatHandler)($req, $threats);
            }

            // Block if not log-only mode
            if (!$this->logOnly && $this->shouldBlock($threats)) {
                $this->handleBlocked($req, $res, $threats);
                return null;
            }
        }

        return $next($req, $res);
    }

    /**
     * Detect threats in the request.
     *
     * @param RequestInterface $req
     * @return array<Threat>
     */
    private function detectThreats(RequestInterface $req): array
    {
        $threats = [];

        // Scan URL path
        if ($this->scanPath) {
            $threats = array_merge($threats, $this->detector->scan($req->path(), 'path'));
        }

        // Scan query parameters
        if ($this->scanQuery) {
            $threats = array_merge($threats, $this->detector->scanArray($req->queryParams(), 'query'));
        }

        // Scan request body
        if ($this->scanBody) {
            $body = $req->body();
            if (is_array($body)) {
                $threats = array_merge($threats, $this->detector->scanArray($body, 'body'));
            } elseif (is_string($body) && $body !== '') {
                $threats = array_merge($threats, $this->detector->scan($body, 'body'));
            }
        }

        // Scan headers
        if ($this->scanHeaders) {
            $headers = $this->filterHeaders($req->headers());
            $threats = array_merge($threats, $this->detector->scanArray($headers, 'headers'));
        }

        // Scan cookies
        if ($this->scanCookies) {
            // Note: RequestInterface doesn't have a getCookies method,
            // so we scan the Cookie header value if available
            $cookieHeader = $req->header('Cookie');
            if ($cookieHeader !== null) {
                $cookies = $this->parseCookieHeader($cookieHeader);
                $threats = array_merge($threats, $this->detector->scanArray($cookies, 'cookies'));
            }
        }

        return $threats;
    }

    /**
     * Filter headers to exclude safe ones.
     *
     * @param array<string, mixed> $headers
     * @return array<string, mixed>
     */
    private function filterHeaders(array $headers): array
    {
        return array_filter($headers, function ($key) {
            return !in_array($key, $this->excludedHeaders, true);
        }, ARRAY_FILTER_USE_KEY);
    }

    /**
     * Parse cookie header into array.
     *
     * @param string $cookieHeader
     * @return array<string, string>
     */
    private function parseCookieHeader(string $cookieHeader): array
    {
        $cookies = [];
        $pairs = explode(';', $cookieHeader);

        foreach ($pairs as $pair) {
            $parts = explode('=', trim($pair), 2);
            if (count($parts) === 2) {
                $cookies[trim($parts[0])] = trim($parts[1]);
            }
        }

        return $cookies;
    }

    /**
     * Check if threats should cause blocking.
     *
     * @param array<Threat> $threats
     * @return bool
     */
    private function shouldBlock(array $threats): bool
    {
        if ($this->blockTypes === null) {
            return true;
        }

        foreach ($threats as $threat) {
            if (in_array($threat->type, $this->blockTypes, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Handle blocked request.
     *
     * @param RequestInterface $req
     * @param ResponseInterface $res
     * @param array<Threat> $threats
     */
    private function handleBlocked(
        RequestInterface $req,
        ResponseInterface $res,
        array $threats,
    ): void {
        if ($this->onBlockHandler !== null) {
            ($this->onBlockHandler)($req, $res, $threats);
            return;
        }

        $res->json([
            'error' => 'Bad Request',
            'message' => 'Potentially malicious content detected',
        ], 400);
    }

    /**
     * Set handler for detected threats.
     *
     * @param callable $handler Function(RequestInterface $req, array<Threat> $threats)
     * @return self
     */
    public function onThreat(callable $handler): self
    {
        $this->onThreatHandler = $handler;
        return $this;
    }

    /**
     * Set custom block handler.
     *
     * @param callable $handler Function(RequestInterface $req, ResponseInterface $res, array<Threat> $threats)
     * @return self
     */
    public function onBlock(callable $handler): self
    {
        $this->onBlockHandler = $handler;
        return $this;
    }

    /**
     * Enable/disable log only mode.
     *
     * @param bool $enabled
     * @return self
     */
    public function setLogOnly(bool $enabled = true): self
    {
        $this->logOnly = $enabled;
        return $this;
    }

    /**
     * Configure what to scan.
     *
     * @param bool $path Scan URL path.
     * @param bool $query Scan query parameters.
     * @param bool $body Scan request body.
     * @param bool $headers Scan headers.
     * @param bool $cookies Scan cookies.
     * @return self
     */
    public function scan(
        bool $path = true,
        bool $query = true,
        bool $body = true,
        bool $headers = false,
        bool $cookies = false,
    ): self {
        $this->scanPath = $path;
        $this->scanQuery = $query;
        $this->scanBody = $body;
        $this->scanHeaders = $headers;
        $this->scanCookies = $cookies;
        return $this;
    }

    /**
     * Exclude fields from scanning.
     *
     * @param array<string> $fields
     * @return self
     */
    public function excludeFields(array $fields): self
    {
        $this->detector->excludeFields($fields);
        return $this;
    }

    /**
     * Mark fields as HTML fields (skip XSS).
     *
     * @param array<string> $fields
     * @return self
     */
    public function htmlFields(array $fields): self
    {
        $this->detector->htmlFields($fields);
        return $this;
    }

    /**
     * Exclude headers from scanning.
     *
     * @param array<string> $headers
     * @return self
     */
    public function excludeHeaders(array $headers): self
    {
        $this->excludedHeaders = array_merge($this->excludedHeaders, $headers);
        return $this;
    }

    /**
     * Set which threat types should cause blocking.
     *
     * @param array<ThreatType> $types
     * @return self
     */
    public function blockOnly(array $types): self
    {
        $this->blockTypes = $types;
        return $this;
    }

    /**
     * Get the threat detector.
     *
     * @return ThreatDetector
     */
    public function getDetector(): ThreatDetector
    {
        return $this->detector;
    }

    /**
     * Create a strict middleware (all detections enabled).
     *
     * @return self
     */
    public static function strict(): self
    {
        return new self(
            detectXss: true,
            detectSqlInjection: true,
            detectPathTraversal: true,
            detectCommandInjection: true,
            logOnly: false,
        );
    }

    /**
     * Create a basic middleware (XSS and SQL Injection only).
     *
     * @return self
     */
    public static function basic(): self
    {
        return new self(
            detectXss: true,
            detectSqlInjection: true,
            detectPathTraversal: false,
            detectCommandInjection: false,
            logOnly: false,
        );
    }

    /**
     * Create a log-only middleware (doesn't block, only logs).
     *
     * @return self
     */
    public static function logOnly(): self
    {
        return (new self(
            detectXss: true,
            detectSqlInjection: true,
            detectPathTraversal: true,
            detectCommandInjection: true,
            logOnly: true,
        ));
    }

    /**
     * Create middleware for API endpoints.
     *
     * @return self
     */
    public static function forApi(): self
    {
        return (new self(
            detectXss: false, // APIs usually don't render HTML
            detectSqlInjection: true,
            detectPathTraversal: true,
            detectCommandInjection: true,
            logOnly: false,
        ))->scan(path: true, query: true, body: true, headers: false, cookies: false);
    }

    /**
     * Create middleware for web forms.
     *
     * @return self
     */
    public static function forForms(): self
    {
        return (new self(
            detectXss: true,
            detectSqlInjection: true,
            detectPathTraversal: false,
            detectCommandInjection: false,
            logOnly: false,
        ))->scan(path: false, query: true, body: true, headers: false, cookies: false);
    }

    /**
     * Create middleware from configuration.
     *
     * @param array<string, mixed> $config
     * @return self
     */
    public static function fromConfig(array $config): self
    {
        $middleware = new self(
            detectXss: $config['detect_xss'] ?? true,
            detectSqlInjection: $config['detect_sql_injection'] ?? true,
            detectPathTraversal: $config['detect_path_traversal'] ?? true,
            detectCommandInjection: $config['detect_command_injection'] ?? false,
            logOnly: $config['log_only'] ?? false,
        );

        if (isset($config['scan'])) {
            $middleware->scan(
                path: $config['scan']['path'] ?? true,
                query: $config['scan']['query'] ?? true,
                body: $config['scan']['body'] ?? true,
                headers: $config['scan']['headers'] ?? false,
                cookies: $config['scan']['cookies'] ?? false,
            );
        }

        if (isset($config['excluded_fields'])) {
            $middleware->excludeFields($config['excluded_fields']);
        }

        if (isset($config['html_fields'])) {
            $middleware->htmlFields($config['html_fields']);
        }

        if (isset($config['excluded_headers'])) {
            $middleware->excludeHeaders($config['excluded_headers']);
        }

        return $middleware;
    }
}
