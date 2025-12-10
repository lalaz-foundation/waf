<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Stubs;

use Lalaz\Web\Http\Contracts\ResponseInterface;
use Lalaz\Web\Http\Contracts\ResponseBodyEmitterInterface;

/**
 * Stub implementation of ResponseInterface for testing.
 */
class StubResponse implements ResponseInterface
{
    private int $statusCode = 200;
    private array $headers = [];
    private string $body = '';
    private bool $sent = false;

    public function status(int $code): self
    {
        $this->statusCode = $code;
        return $this;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    public function addHeader(string $name, string $value): self
    {
        $this->headers[$name] = $value;
        return $this;
    }

    public function header(string $name, string $value): self
    {
        return $this->addHeader($name, $value);
    }

    public function withHeaders(array $headers): self
    {
        foreach ($headers as $name => $value) {
            $this->headers[$name] = $value;
        }
        return $this;
    }

    public function headers(): array
    {
        return $this->headers;
    }

    public function body(): string
    {
        return $this->body;
    }

    public function isStreamed(): bool
    {
        return false;
    }

    public function sendBody(ResponseBodyEmitterInterface $emitter): void
    {
        $emitter->emit($this->body);
    }

    public function setBody(string $content): self
    {
        $this->body = $content;
        return $this;
    }

    public function append(string $content): self
    {
        $this->body .= $content;
        return $this;
    }

    public function redirect(string $url, bool $allowExternal = false): void
    {
        $this->status(302);
        $this->header('Location', $url);
        $this->sent = true;
    }

    public function noContent(array $headers = []): void
    {
        $this->status(204);
        $this->withHeaders($headers);
        $this->sent = true;
    }

    public function created(string $location, mixed $data = null): void
    {
        $this->status(201);
        $this->header('Location', $location);
        if ($data !== null) {
            $this->body = json_encode($data);
        }
        $this->sent = true;
    }

    public function download(
        string $filePath,
        ?string $fileName = null,
        array $headers = [],
    ): void {
        $this->sent = true;
    }

    public function stream(
        callable $callback,
        int $statusCode = 200,
        array $headers = [],
    ): void {
        $this->status($statusCode);
        $this->withHeaders($headers);
        $this->sent = true;
    }

    public function json($data = [], $statusCode = 200): void
    {
        $this->status($statusCode);
        $this->header('Content-Type', 'application/json');
        $this->body = json_encode($data);
        $this->sent = true;
    }

    public function send(
        string $content = '',
        int $statusCode = 200,
        array $headers = [],
        ?string $contentType = null,
    ): void {
        $this->status($statusCode);
        $this->withHeaders($headers);
        if ($contentType !== null) {
            $this->header('Content-Type', $contentType);
        }
        $this->body = $content;
        $this->sent = true;
    }

    public function end(): void
    {
        $this->headers = [];
        $this->body = '';
        $this->statusCode = 200;
    }

    // Test helper methods
    public function isSent(): bool
    {
        return $this->sent;
    }

    public function hasHeader(string $name): bool
    {
        return isset($this->headers[$name]);
    }

    public function getHeader(string $name): ?string
    {
        return $this->headers[$name] ?? null;
    }

    public function getJsonBody(): array
    {
        return json_decode($this->body, true) ?? [];
    }
}
