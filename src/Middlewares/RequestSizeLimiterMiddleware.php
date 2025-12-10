<?php

declare(strict_types=1);

namespace Lalaz\Waf\Middlewares;

use Lalaz\Web\Http\Contracts\MiddlewareInterface;
use Lalaz\Web\Http\Contracts\RequestInterface;
use Lalaz\Web\Http\Contracts\ResponseInterface;

/**
 * Request Size Limiter Middleware
 *
 * Limits the size of incoming requests to prevent DoS attacks
 * via large payloads, long URLs, or oversized headers.
 *
 * @example Basic usage:
 * ```php
 * $middleware = new RequestSizeLimiterMiddleware(
 *     maxBodySize: 10 * 1024 * 1024,  // 10MB
 *     maxUrlLength: 2048,
 *     maxHeaderSize: 8192,
 * );
 * ```
 *
 * @example For API endpoints:
 * ```php
 * $middleware = RequestSizeLimiterMiddleware::forApi();
 * ```
 *
 * @example For file uploads:
 * ```php
 * $middleware = RequestSizeLimiterMiddleware::forUploads();
 * ```
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hello@lalaz.dev>
 * @link https://lalaz.dev
 */
class RequestSizeLimiterMiddleware implements MiddlewareInterface
{
    // Size constants
    public const KB = 1024;
    public const MB = 1024 * 1024;
    public const GB = 1024 * 1024 * 1024;

    /**
     * @var int|null Maximum body size in bytes (null = no limit).
     */
    private ?int $maxBodySize;

    /**
     * @var int|null Maximum URL length (null = no limit).
     */
    private ?int $maxUrlLength;

    /**
     * @var int|null Maximum total header size in bytes (null = no limit).
     */
    private ?int $maxHeaderSize;

    /**
     * @var int|null Maximum single header value length (null = no limit).
     */
    private ?int $maxSingleHeaderSize;

    /**
     * @var int|null Maximum number of headers (null = no limit).
     */
    private ?int $maxHeaderCount;

    /**
     * @var int|null Maximum query string length (null = no limit).
     */
    private ?int $maxQueryStringLength;

    /**
     * @var int|null Maximum number of query parameters (null = no limit).
     */
    private ?int $maxQueryParams;

    /**
     * @var int|null Maximum JSON depth (null = no limit).
     */
    private ?int $maxJsonDepth;

    /**
     * @var int|null Maximum number of fields in body (null = no limit).
     */
    private ?int $maxBodyFields;

    /**
     * @var callable|null Custom handler for oversized requests.
     */
    private $onExceededHandler = null;

    /**
     * Create a new request size limiter middleware.
     *
     * @param int|null $maxBodySize Maximum body size in bytes.
     * @param int|null $maxUrlLength Maximum URL length.
     * @param int|null $maxHeaderSize Maximum total header size in bytes.
     * @param int|null $maxSingleHeaderSize Maximum single header value length.
     * @param int|null $maxHeaderCount Maximum number of headers.
     * @param int|null $maxQueryStringLength Maximum query string length.
     * @param int|null $maxQueryParams Maximum number of query parameters.
     * @param int|null $maxJsonDepth Maximum JSON nesting depth.
     * @param int|null $maxBodyFields Maximum number of body fields.
     */
    public function __construct(
        ?int $maxBodySize = 10 * self::MB,
        ?int $maxUrlLength = 2048,
        ?int $maxHeaderSize = 8 * self::KB,
        ?int $maxSingleHeaderSize = 4 * self::KB,
        ?int $maxHeaderCount = 100,
        ?int $maxQueryStringLength = 2048,
        ?int $maxQueryParams = 100,
        ?int $maxJsonDepth = 32,
        ?int $maxBodyFields = 1000,
    ) {
        $this->maxBodySize = $maxBodySize;
        $this->maxUrlLength = $maxUrlLength;
        $this->maxHeaderSize = $maxHeaderSize;
        $this->maxSingleHeaderSize = $maxSingleHeaderSize;
        $this->maxHeaderCount = $maxHeaderCount;
        $this->maxQueryStringLength = $maxQueryStringLength;
        $this->maxQueryParams = $maxQueryParams;
        $this->maxJsonDepth = $maxJsonDepth;
        $this->maxBodyFields = $maxBodyFields;
    }

    /**
     * Handle the incoming request.
     */
    public function handle(RequestInterface $req, ResponseInterface $res, callable $next): mixed
    {
        // Check URL length
        $violation = $this->checkUrlLength($req);
        if ($violation !== null) {
            $this->handleExceeded($req, $res, $violation);
            return null;
        }

        // Check query string
        $violation = $this->checkQueryString($req);
        if ($violation !== null) {
            $this->handleExceeded($req, $res, $violation);
            return null;
        }

        // Check headers
        $violation = $this->checkHeaders($req);
        if ($violation !== null) {
            $this->handleExceeded($req, $res, $violation);
            return null;
        }

        // Check body size
        $violation = $this->checkBodySize($req);
        if ($violation !== null) {
            $this->handleExceeded($req, $res, $violation);
            return null;
        }

        // Check body fields
        $violation = $this->checkBodyFields($req);
        if ($violation !== null) {
            $this->handleExceeded($req, $res, $violation);
            return null;
        }

        // Check JSON depth
        $violation = $this->checkJsonDepth($req);
        if ($violation !== null) {
            $this->handleExceeded($req, $res, $violation);
            return null;
        }

        return $next($req, $res);
    }

    /**
     * Check URL length.
     *
     * @return array{type: string, limit: int, actual: int, message: string}|null
     */
    private function checkUrlLength(RequestInterface $req): ?array
    {
        if ($this->maxUrlLength === null) {
            return null;
        }

        $url = $req->uri();
        $length = strlen($url);

        if ($length > $this->maxUrlLength) {
            return [
                'type' => 'url_length',
                'limit' => $this->maxUrlLength,
                'actual' => $length,
                'message' => "URL length ({$length}) exceeds maximum ({$this->maxUrlLength})",
            ];
        }

        return null;
    }

    /**
     * Check query string.
     *
     * @return array{type: string, limit: int, actual: int, message: string}|null
     */
    private function checkQueryString(RequestInterface $req): ?array
    {
        $queryParams = $req->queryParams();

        // Check query string length
        if ($this->maxQueryStringLength !== null) {
            $queryString = http_build_query($queryParams);
            $length = strlen($queryString);

            if ($length > $this->maxQueryStringLength) {
                return [
                    'type' => 'query_string_length',
                    'limit' => $this->maxQueryStringLength,
                    'actual' => $length,
                    'message' => "Query string length ({$length}) exceeds maximum ({$this->maxQueryStringLength})",
                ];
            }
        }

        // Check query param count
        if ($this->maxQueryParams !== null) {
            $count = $this->countParams($queryParams);

            if ($count > $this->maxQueryParams) {
                return [
                    'type' => 'query_param_count',
                    'limit' => $this->maxQueryParams,
                    'actual' => $count,
                    'message' => "Query parameter count ({$count}) exceeds maximum ({$this->maxQueryParams})",
                ];
            }
        }

        return null;
    }

    /**
     * Check headers.
     *
     * @return array{type: string, limit: int, actual: int, message: string}|null
     */
    private function checkHeaders(RequestInterface $req): ?array
    {
        $headers = $req->headers();

        // Check header count
        if ($this->maxHeaderCount !== null) {
            $count = count($headers);

            if ($count > $this->maxHeaderCount) {
                return [
                    'type' => 'header_count',
                    'limit' => $this->maxHeaderCount,
                    'actual' => $count,
                    'message' => "Header count ({$count}) exceeds maximum ({$this->maxHeaderCount})",
                ];
            }
        }

        // Check total header size and individual header sizes
        $totalSize = 0;

        foreach ($headers as $name => $value) {
            $headerValue = is_array($value) ? implode(', ', $value) : (string) $value;
            $headerSize = strlen($name) + strlen($headerValue) + 4; // +4 for ": " and "\r\n"
            $totalSize += $headerSize;

            // Check single header size
            if ($this->maxSingleHeaderSize !== null) {
                $valueLength = strlen($headerValue);

                if ($valueLength > $this->maxSingleHeaderSize) {
                    return [
                        'type' => 'single_header_size',
                        'limit' => $this->maxSingleHeaderSize,
                        'actual' => $valueLength,
                        'message' => "Header '{$name}' value length ({$valueLength}) exceeds maximum ({$this->maxSingleHeaderSize})",
                    ];
                }
            }
        }

        // Check total header size
        if ($this->maxHeaderSize !== null && $totalSize > $this->maxHeaderSize) {
            return [
                'type' => 'total_header_size',
                'limit' => $this->maxHeaderSize,
                'actual' => $totalSize,
                'message' => "Total header size ({$totalSize}) exceeds maximum ({$this->maxHeaderSize})",
            ];
        }

        return null;
    }

    /**
     * Check body size.
     *
     * @return array{type: string, limit: int, actual: int, message: string}|null
     */
    private function checkBodySize(RequestInterface $req): ?array
    {
        if ($this->maxBodySize === null) {
            return null;
        }

        // Try Content-Length header first
        $contentLength = $req->header('Content-Length');

        if ($contentLength !== null) {
            $size = (int) $contentLength;

            if ($size > $this->maxBodySize) {
                return [
                    'type' => 'body_size',
                    'limit' => $this->maxBodySize,
                    'actual' => $size,
                    'message' => "Body size ({$this->formatBytes($size)}) exceeds maximum ({$this->formatBytes($this->maxBodySize)})",
                ];
            }
        }

        // Also check actual body if available
        $body = $req->body();

        if (is_string($body)) {
            $size = strlen($body);

            if ($size > $this->maxBodySize) {
                return [
                    'type' => 'body_size',
                    'limit' => $this->maxBodySize,
                    'actual' => $size,
                    'message' => "Body size ({$this->formatBytes($size)}) exceeds maximum ({$this->formatBytes($this->maxBodySize)})",
                ];
            }
        }

        return null;
    }

    /**
     * Check body fields count.
     *
     * @return array{type: string, limit: int, actual: int, message: string}|null
     */
    private function checkBodyFields(RequestInterface $req): ?array
    {
        if ($this->maxBodyFields === null) {
            return null;
        }

        $body = $req->body();

        if (!is_array($body)) {
            return null;
        }

        $count = $this->countParams($body);

        if ($count > $this->maxBodyFields) {
            return [
                'type' => 'body_field_count',
                'limit' => $this->maxBodyFields,
                'actual' => $count,
                'message' => "Body field count ({$count}) exceeds maximum ({$this->maxBodyFields})",
            ];
        }

        return null;
    }

    /**
     * Check JSON depth.
     *
     * @return array{type: string, limit: int, actual: int, message: string}|null
     */
    private function checkJsonDepth(RequestInterface $req): ?array
    {
        if ($this->maxJsonDepth === null) {
            return null;
        }

        if (!$req->isJson()) {
            return null;
        }

        $body = $req->body();

        if (!is_array($body)) {
            return null;
        }

        $depth = $this->getArrayDepth($body);

        if ($depth > $this->maxJsonDepth) {
            return [
                'type' => 'json_depth',
                'limit' => $this->maxJsonDepth,
                'actual' => $depth,
                'message' => "JSON depth ({$depth}) exceeds maximum ({$this->maxJsonDepth})",
            ];
        }

        return null;
    }

    /**
     * Count parameters recursively.
     *
     * @param array<mixed> $params
     * @return int
     */
    private function countParams(array $params): int
    {
        $count = 0;

        foreach ($params as $value) {
            $count++;
            if (is_array($value)) {
                $count += $this->countParams($value);
            }
        }

        return $count;
    }

    /**
     * Get the depth of a nested array.
     *
     * @param array<mixed> $array
     * @param int $depth
     * @return int
     */
    private function getArrayDepth(array $array, int $depth = 1): int
    {
        $maxDepth = $depth;

        foreach ($array as $value) {
            if (is_array($value)) {
                $childDepth = $this->getArrayDepth($value, $depth + 1);
                $maxDepth = max($maxDepth, $childDepth);
            }
        }

        return $maxDepth;
    }

    /**
     * Format bytes to human-readable string.
     */
    private function formatBytes(int $bytes): string
    {
        if ($bytes >= self::GB) {
            return round($bytes / self::GB, 2) . ' GB';
        }
        if ($bytes >= self::MB) {
            return round($bytes / self::MB, 2) . ' MB';
        }
        if ($bytes >= self::KB) {
            return round($bytes / self::KB, 2) . ' KB';
        }
        return $bytes . ' bytes';
    }

    /**
     * Handle exceeded limit.
     *
     * @param RequestInterface $req
     * @param ResponseInterface $res
     * @param array{type: string, limit: int, actual: int, message: string} $violation
     */
    private function handleExceeded(
        RequestInterface $req,
        ResponseInterface $res,
        array $violation,
    ): void {
        if ($this->onExceededHandler !== null) {
            ($this->onExceededHandler)($req, $res, $violation);
            return;
        }

        $res->json([
            'error' => 'Payload Too Large',
            'message' => $violation['message'],
        ], 413);
    }

    /**
     * Set custom handler for exceeded limits.
     *
     * @param callable $handler Function(RequestInterface $req, ResponseInterface $res, array $violation)
     * @return self
     */
    public function onExceeded(callable $handler): self
    {
        $this->onExceededHandler = $handler;
        return $this;
    }

    /**
     * Set maximum body size.
     *
     * @param int|null $bytes
     * @return self
     */
    public function maxBody(?int $bytes): self
    {
        $this->maxBodySize = $bytes;
        return $this;
    }

    /**
     * Set maximum URL length.
     *
     * @param int|null $length
     * @return self
     */
    public function maxUrl(?int $length): self
    {
        $this->maxUrlLength = $length;
        return $this;
    }

    /**
     * Set maximum header size.
     *
     * @param int|null $bytes
     * @return self
     */
    public function maxHeaders(?int $bytes): self
    {
        $this->maxHeaderSize = $bytes;
        return $this;
    }

    /**
     * Set maximum single header value size.
     *
     * @param int|null $bytes
     * @return self
     */
    public function maxSingleHeader(?int $bytes): self
    {
        $this->maxSingleHeaderSize = $bytes;
        return $this;
    }

    /**
     * Set maximum header count.
     *
     * @param int|null $count
     * @return self
     */
    public function maxHeaderCount(?int $count): self
    {
        $this->maxHeaderCount = $count;
        return $this;
    }

    /**
     * Set maximum query string length.
     *
     * @param int|null $length
     * @return self
     */
    public function maxQueryString(?int $length): self
    {
        $this->maxQueryStringLength = $length;
        return $this;
    }

    /**
     * Set maximum query parameter count.
     *
     * @param int|null $count
     * @return self
     */
    public function maxQueryParams(?int $count): self
    {
        $this->maxQueryParams = $count;
        return $this;
    }

    /**
     * Set maximum JSON depth.
     *
     * @param int|null $depth
     * @return self
     */
    public function maxJsonDepth(?int $depth): self
    {
        $this->maxJsonDepth = $depth;
        return $this;
    }

    /**
     * Set maximum body field count.
     *
     * @param int|null $count
     * @return self
     */
    public function maxBodyFields(?int $count): self
    {
        $this->maxBodyFields = $count;
        return $this;
    }

    /**
     * Check if a size would pass the body limit.
     *
     * @param int $bytes
     * @return bool
     */
    public function wouldAllowBodySize(int $bytes): bool
    {
        return $this->maxBodySize === null || $bytes <= $this->maxBodySize;
    }

    /**
     * Get the maximum body size.
     *
     * @return int|null
     */
    public function getMaxBodySize(): ?int
    {
        return $this->maxBodySize;
    }

    /**
     * Get the maximum URL length.
     *
     * @return int|null
     */
    public function getMaxUrlLength(): ?int
    {
        return $this->maxUrlLength;
    }

    /**
     * Create a middleware with no limits (passthrough).
     *
     * @return self
     */
    public static function unlimited(): self
    {
        return new self(
            maxBodySize: null,
            maxUrlLength: null,
            maxHeaderSize: null,
            maxSingleHeaderSize: null,
            maxHeaderCount: null,
            maxQueryStringLength: null,
            maxQueryParams: null,
            maxJsonDepth: null,
            maxBodyFields: null,
        );
    }

    /**
     * Create a middleware for API endpoints (strict limits).
     *
     * @return self
     */
    public static function forApi(): self
    {
        return new self(
            maxBodySize: 1 * self::MB,
            maxUrlLength: 2048,
            maxHeaderSize: 8 * self::KB,
            maxSingleHeaderSize: 4 * self::KB,
            maxHeaderCount: 50,
            maxQueryStringLength: 1024,
            maxQueryParams: 50,
            maxJsonDepth: 20,
            maxBodyFields: 100,
        );
    }

    /**
     * Create a middleware for file uploads (relaxed body limit).
     *
     * @param int $maxFileSize Maximum file size in bytes (default 100MB).
     * @return self
     */
    public static function forUploads(int $maxFileSize = 100 * self::MB): self
    {
        return new self(
            maxBodySize: $maxFileSize,
            maxUrlLength: 2048,
            maxHeaderSize: 16 * self::KB,
            maxSingleHeaderSize: 8 * self::KB,
            maxHeaderCount: 100,
            maxQueryStringLength: 1024,
            maxQueryParams: 50,
            maxJsonDepth: null,
            maxBodyFields: null,
        );
    }

    /**
     * Create a middleware for web forms.
     *
     * @return self
     */
    public static function forForms(): self
    {
        return new self(
            maxBodySize: 5 * self::MB,
            maxUrlLength: 4096,
            maxHeaderSize: 8 * self::KB,
            maxSingleHeaderSize: 4 * self::KB,
            maxHeaderCount: 50,
            maxQueryStringLength: 2048,
            maxQueryParams: 100,
            maxJsonDepth: 10,
            maxBodyFields: 500,
        );
    }

    /**
     * Create a middleware for GraphQL endpoints.
     *
     * @return self
     */
    public static function forGraphQL(): self
    {
        return new self(
            maxBodySize: 1 * self::MB,
            maxUrlLength: 2048,
            maxHeaderSize: 8 * self::KB,
            maxSingleHeaderSize: 4 * self::KB,
            maxHeaderCount: 50,
            maxQueryStringLength: 4096, // GraphQL often uses long query strings
            maxQueryParams: 20,
            maxJsonDepth: 15,
            maxBodyFields: 200,
        );
    }

    /**
     * Create a strict middleware for maximum security.
     *
     * @return self
     */
    public static function strict(): self
    {
        return new self(
            maxBodySize: 256 * self::KB,
            maxUrlLength: 1024,
            maxHeaderSize: 4 * self::KB,
            maxSingleHeaderSize: 2 * self::KB,
            maxHeaderCount: 30,
            maxQueryStringLength: 512,
            maxQueryParams: 20,
            maxJsonDepth: 10,
            maxBodyFields: 50,
        );
    }

    /**
     * Create middleware from configuration array.
     *
     * @param array<string, mixed> $config
     * @return self
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            maxBodySize: $config['max_body_size'] ?? 10 * self::MB,
            maxUrlLength: $config['max_url_length'] ?? 2048,
            maxHeaderSize: $config['max_header_size'] ?? 8 * self::KB,
            maxSingleHeaderSize: $config['max_single_header_size'] ?? 4 * self::KB,
            maxHeaderCount: $config['max_header_count'] ?? 100,
            maxQueryStringLength: $config['max_query_string_length'] ?? 2048,
            maxQueryParams: $config['max_query_params'] ?? 100,
            maxJsonDepth: $config['max_json_depth'] ?? 32,
            maxBodyFields: $config['max_body_fields'] ?? 1000,
        );
    }
}
