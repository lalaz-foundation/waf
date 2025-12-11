<?php

declare(strict_types=1);

namespace Lalaz\Waf\RateLimit;

/**
 * Rate Limit Exceeded Exception
 *
 * Thrown when a rate limit has been exceeded.
 * Contains information about when the limit will reset.
 *
 * @package lalaz/waf
 * @author Lalaz Framework <hi@lalaz.dev>
 * @link https://lalaz.dev
 */
class RateLimitExceededException extends \Exception
{
    /**
     * @var int Seconds until the limit resets
     */
    private int $retryAfter;

    /**
     * @var int Maximum attempts allowed
     */
    private int $limit;

    /**
     * Create a new RateLimitExceededException.
     *
     * @param string $message Error message
     * @param int $retryAfter Seconds until limit resets
     * @param int $limit Maximum attempts allowed
     * @param int $code HTTP status code (default: 429)
     * @param \Throwable|null $previous Previous exception
     */
    public function __construct(
        string $message = 'Too Many Requests',
        int $retryAfter = 60,
        int $limit = 60,
        int $code = 429,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
        $this->retryAfter = $retryAfter;
        $this->limit = $limit;
    }

    /**
     * Get the number of seconds until the rate limit resets.
     *
     * @return int
     */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }

    /**
     * Get the rate limit.
     *
     * @return int
     */
    public function getLimit(): int
    {
        return $this->limit;
    }

    /**
     * Get HTTP headers for the rate limit response.
     *
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return [
            'Retry-After' => (string) $this->retryAfter,
            'X-RateLimit-Limit' => (string) $this->limit,
            'X-RateLimit-Remaining' => '0',
        ];
    }
}
