<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * HTTP Method Filtering Middleware
 *
 * Restricts allowed HTTP methods to reduce attack surface.
 * Blocks requests with unexpected or dangerous methods.
 *
 * @example Allow only common methods:
 * ```php
 * $middleware = new HttpMethodMiddleware(['GET', 'POST', 'PUT', 'DELETE']);
 * ```
 *
 * @example For read-only API:
 * ```php
 * $middleware = HttpMethodMiddleware::readOnly();
 * ```
 *
 * @example For REST API:
 * ```php
 * $middleware = HttpMethodMiddleware::restful();
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 * @link https://lalaz.dev
 */
class HttpMethodMiddleware implements MiddlewareInterface
{
    /**
     * Standard HTTP methods.
     */
    public const GET = 'GET';
    public const POST = 'POST';
    public const PUT = 'PUT';
    public const PATCH = 'PATCH';
    public const DELETE = 'DELETE';
    public const HEAD = 'HEAD';
    public const OPTIONS = 'OPTIONS';
    public const TRACE = 'TRACE';
    public const CONNECT = 'CONNECT';

    /**
     * @var array<string> Allowed HTTP methods.
     */
    private array $allowedMethods;

    /**
     * @var bool Whether to allow OPTIONS for CORS preflight.
     */
    private bool $allowOptions = true;

    /**
     * @var bool Whether to allow HEAD requests (treated as GET).
     */
    private bool $allowHead = true;

    /**
     * @var callable|null Custom handler for blocked requests.
     */
    private $onBlockHandler = null;

    /**
     * Create a new HTTP method middleware.
     *
     * @param array<string> $allowedMethods List of allowed HTTP methods.
     */
    public function __construct(array $allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
    {
        $this->allowedMethods = array_map('strtoupper', $allowedMethods);
    }

    /**
     * Handle the incoming request.
     */
    public function handle(RequestInterface $req, ResponseInterface $res, callable $next): mixed
    {
        $method = strtoupper($req->method());

        // Always allow OPTIONS if enabled (for CORS preflight)
        if ($this->allowOptions && $method === self::OPTIONS) {
            return $next($req, $res);
        }

        // Allow HEAD if enabled (semantically same as GET)
        if ($this->allowHead && $method === self::HEAD) {
            if (in_array(self::GET, $this->allowedMethods, true)) {
                return $next($req, $res);
            }
        }

        // Check if method is allowed
        if (in_array($method, $this->allowedMethods, true)) {
            return $next($req, $res);
        }

        // Method not allowed
        $this->handleBlocked($req, $res, $method);
        return null;
    }

    /**
     * Handle a blocked request.
     */
    private function handleBlocked(
        RequestInterface $req,
        ResponseInterface $res,
        string $method,
    ): void {
        if ($this->onBlockHandler !== null) {
            ($this->onBlockHandler)($req, $res, $method, $this->allowedMethods);
            return;
        }

        $res->header('Allow', implode(', ', $this->getAllowedMethodsForHeader()));
        $res->json([
            'error' => 'Method Not Allowed',
            'message' => "The {$method} method is not allowed for this resource.",
            'allowed_methods' => $this->getAllowedMethodsForHeader(),
        ], 405);
    }

    /**
     * Get allowed methods including implicit ones for the Allow header.
     *
     * @return array<string>
     */
    private function getAllowedMethodsForHeader(): array
    {
        $methods = $this->allowedMethods;

        if ($this->allowOptions && !in_array(self::OPTIONS, $methods, true)) {
            $methods[] = self::OPTIONS;
        }

        if ($this->allowHead && in_array(self::GET, $methods, true) && !in_array(self::HEAD, $methods, true)) {
            $methods[] = self::HEAD;
        }

        sort($methods);
        return $methods;
    }

    // ========================================
    // Configuration Methods
    // ========================================

    /**
     * Set allowed methods.
     *
     * @param array<string> $methods
     * @return self
     */
    public function allow(array $methods): self
    {
        $this->allowedMethods = array_map('strtoupper', $methods);
        return $this;
    }

    /**
     * Add a method to the allowed list.
     *
     * @param string $method
     * @return self
     */
    public function addMethod(string $method): self
    {
        $method = strtoupper($method);
        if (!in_array($method, $this->allowedMethods, true)) {
            $this->allowedMethods[] = $method;
        }
        return $this;
    }

    /**
     * Remove a method from the allowed list.
     *
     * @param string $method
     * @return self
     */
    public function removeMethod(string $method): self
    {
        $method = strtoupper($method);
        $this->allowedMethods = array_filter(
            $this->allowedMethods,
            fn ($m) => $m !== $method
        );
        return $this;
    }

    /**
     * Configure whether to allow OPTIONS requests (for CORS).
     *
     * @param bool $allow
     * @return self
     */
    public function allowOptionsRequests(bool $allow = true): self
    {
        $this->allowOptions = $allow;
        return $this;
    }

    /**
     * Configure whether to allow HEAD requests.
     *
     * @param bool $allow
     * @return self
     */
    public function allowHeadRequests(bool $allow = true): self
    {
        $this->allowHead = $allow;
        return $this;
    }

    /**
     * Set custom handler for blocked requests.
     *
     * @param callable $handler Function(RequestInterface, ResponseInterface, string $method, array $allowed)
     * @return self
     */
    public function onBlock(callable $handler): self
    {
        $this->onBlockHandler = $handler;
        return $this;
    }

    // ========================================
    // Getters
    // ========================================

    /**
     * Get the list of allowed methods.
     *
     * @return array<string>
     */
    public function getAllowedMethods(): array
    {
        return $this->allowedMethods;
    }

    /**
     * Check if a method is allowed.
     *
     * @param string $method
     * @return bool
     */
    public function isMethodAllowed(string $method): bool
    {
        $method = strtoupper($method);

        if ($this->allowOptions && $method === self::OPTIONS) {
            return true;
        }

        if ($this->allowHead && $method === self::HEAD && in_array(self::GET, $this->allowedMethods, true)) {
            return true;
        }

        return in_array($method, $this->allowedMethods, true);
    }

    // ========================================
    // Factory Methods
    // ========================================

    /**
     * Create middleware for read-only access (GET only).
     *
     * @return self
     */
    public static function readOnly(): self
    {
        return new self([self::GET]);
    }

    /**
     * Create middleware for standard web forms (GET + POST).
     *
     * @return self
     */
    public static function webForms(): self
    {
        return new self([self::GET, self::POST]);
    }

    /**
     * Create middleware for RESTful APIs.
     *
     * @return self
     */
    public static function restful(): self
    {
        return new self([
            self::GET,
            self::POST,
            self::PUT,
            self::PATCH,
            self::DELETE,
        ]);
    }

    /**
     * Create middleware that blocks dangerous methods (TRACE, CONNECT).
     *
     * @return self
     */
    public static function safe(): self
    {
        return new self([
            self::GET,
            self::POST,
            self::PUT,
            self::PATCH,
            self::DELETE,
            self::HEAD,
            self::OPTIONS,
        ]);
    }

    /**
     * Create middleware that allows all standard methods.
     *
     * @return self
     */
    public static function all(): self
    {
        return new self([
            self::GET,
            self::POST,
            self::PUT,
            self::PATCH,
            self::DELETE,
            self::HEAD,
            self::OPTIONS,
            self::TRACE,
            self::CONNECT,
        ]);
    }

    /**
     * Create middleware for specific route (single method).
     *
     * @param string $method
     * @return self
     */
    public static function only(string $method): self
    {
        return new self([strtoupper($method)]);
    }

    /**
     * Create middleware from configuration array.
     *
     * @param array<string, mixed> $config
     * @return self
     */
    public static function fromConfig(array $config): self
    {
        $middleware = new self($config['allowed_methods'] ?? ['GET', 'POST']);

        if (isset($config['allow_options'])) {
            $middleware->allowOptionsRequests((bool) $config['allow_options']);
        }

        if (isset($config['allow_head'])) {
            $middleware->allowHeadRequests((bool) $config['allow_head']);
        }

        return $middleware;
    }
}
