<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Stubs;

use Lalaz\Web\Http\Contracts\RequestInterface;

/**
 * Stub implementation of RequestInterface for testing.
 */
class StubRequest implements RequestInterface
{
    private array $attributes = [];

    public function __construct(
        private string $httpMethod = 'GET',
        private string $path = '/',
        private array $routeParams = [],
        private array $headers = [],
        private ?object $user = null,
        private ?array $queryParams = [],
        private mixed $body = [],
        private array $cookies = [],
        private string $ip = '127.0.0.1',
    ) {
        $this->queryParams ??= [];
    }

    public function method(): string
    {
        return $this->httpMethod;
    }

    public function setMethod(string $method): void
    {
        $this->httpMethod = $method;
    }

    public function path(): string
    {
        return $this->path;
    }

    public function uri(): string
    {
        return $this->path;
    }

    public function params(): array
    {
        return array_merge($this->routeParams, $this->queryParams);
    }

    public function param(string $name, mixed $default = null): mixed
    {
        return $this->params()[$name] ?? $default;
    }

    public function routeParams(): array
    {
        return $this->routeParams;
    }

    public function routeParam(string $name, mixed $default = null): mixed
    {
        return $this->routeParams[$name] ?? $default;
    }

    public function queryParams(): array
    {
        return $this->queryParams;
    }

    public function queryParam(string $name, mixed $default = null): mixed
    {
        return $this->queryParams[$name] ?? $default;
    }

    public function body(): mixed
    {
        return $this->body;
    }

    public function input(string $name, mixed $default = null): mixed
    {
        return $this->body[$name] ?? $default;
    }

    public function all(): array
    {
        return array_merge($this->params(), is_array($this->body) ? $this->body : []);
    }

    public function json(?string $key = null, mixed $default = null): mixed
    {
        if ($key === null) {
            return $this->body;
        }
        return $this->body[$key] ?? $default;
    }

    public function cookie(string $name): mixed
    {
        return $this->cookies[$name] ?? null;
    }

    public function hasCookie(string $name): bool
    {
        return isset($this->cookies[$name]);
    }

    public function isJson(): bool
    {
        $contentType = $this->header('Content-Type');
        return $contentType !== null && str_contains($contentType, 'application/json');
    }

    public function headers(): array
    {
        return $this->headers;
    }

    public function header(string $name, mixed $default = null): mixed
    {
        return $this->headers[$name] ?? $default;
    }

    public function has(string $key): bool
    {
        return isset($this->all()[$key]);
    }

    public function boolean(string $key, bool $default = false): bool
    {
        $value = $this->input($key);
        if ($value === null) {
            return $default;
        }
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    public function file(string $key)
    {
        return null;
    }

    public function ip(): string
    {
        return $this->ip;
    }

    public function userAgent(): string
    {
        return $this->header('User-Agent') ?? '';
    }

    public function wantsJson(): bool
    {
        $accept = $this->header('Accept') ?? '';
        return str_contains($accept, 'application/json');
    }

    public function isSecure(): bool
    {
        return false;
    }

    public function user(): ?object
    {
        return $this->user;
    }

    public function getAttribute(string $name, mixed $default = null): mixed
    {
        return $this->attributes[$name] ?? $default;
    }

    public function setAttribute(string $name, mixed $value): void
    {
        $this->attributes[$name] = $value;
    }

    // Factory methods for testing convenience
    public static function create(
        string $method = 'GET',
        string $path = '/',
        array $headers = [],
        string $ip = '127.0.0.1',
        ?object $user = null,
    ): self {
        return new self(
            httpMethod: $method,
            path: $path,
            headers: $headers,
            ip: $ip,
            user: $user,
        );
    }
}
