<?php

declare(strict_types=1);

namespace Lalaz\Waf\IpFilter;

/**
 * IP List manager for whitelist and blacklist operations.
 *
 * Manages lists of IPs with support for:
 * - Adding/removing IPs dynamically
 * - Persistence via callbacks
 * - Pattern matching (exact, CIDR, wildcard, range)
 *
 * @package lalaz/waf
 */
final class IpList
{
    /**
     * @var array<string> List of IP patterns.
     */
    private array $patterns = [];

    /**
     * @var string Name/identifier for this list.
     */
    private string $name;

    /**
     * @var callable|null Callback for persisting changes.
     */
    private $persistCallback = null;

    /**
     * Create a new IP list.
     *
     * @param string $name The name of this list.
     * @param array<string> $patterns Initial patterns.
     */
    public function __construct(string $name = 'default', array $patterns = [])
    {
        $this->name = $name;
        $this->patterns = array_values(array_unique($patterns));
    }

    /**
     * Add an IP or pattern to the list.
     *
     * @param string $pattern The IP or pattern to add.
     * @return self
     */
    public function add(string $pattern): self
    {
        $pattern = trim($pattern);

        if ($pattern !== '' && !in_array($pattern, $this->patterns, true)) {
            $this->patterns[] = $pattern;
            $this->persist();
        }

        return $this;
    }

    /**
     * Add multiple IPs or patterns to the list.
     *
     * @param array<string> $patterns The patterns to add.
     * @return self
     */
    public function addMany(array $patterns): self
    {
        foreach ($patterns as $pattern) {
            $this->add($pattern);
        }

        return $this;
    }

    /**
     * Remove an IP or pattern from the list.
     *
     * @param string $pattern The IP or pattern to remove.
     * @return self
     */
    public function remove(string $pattern): self
    {
        $pattern = trim($pattern);
        $key = array_search($pattern, $this->patterns, true);

        if ($key !== false) {
            unset($this->patterns[$key]);
            $this->patterns = array_values($this->patterns);
            $this->persist();
        }

        return $this;
    }

    /**
     * Remove multiple IPs or patterns from the list.
     *
     * @param array<string> $patterns The patterns to remove.
     * @return self
     */
    public function removeMany(array $patterns): self
    {
        foreach ($patterns as $pattern) {
            $this->remove($pattern);
        }

        return $this;
    }

    /**
     * Check if an IP matches any pattern in this list.
     *
     * @param string $ip The IP to check.
     * @return bool True if the IP matches.
     */
    public function contains(string $ip): bool
    {
        return IpMatcher::matchesAny($ip, $this->patterns);
    }

    /**
     * Check if a pattern exists in the list (exact match).
     *
     * @param string $pattern The pattern to check.
     * @return bool True if the pattern exists.
     */
    public function has(string $pattern): bool
    {
        return in_array(trim($pattern), $this->patterns, true);
    }

    /**
     * Clear all patterns from the list.
     *
     * @return self
     */
    public function clear(): self
    {
        $this->patterns = [];
        $this->persist();

        return $this;
    }

    /**
     * Get all patterns in the list.
     *
     * @return array<string>
     */
    public function all(): array
    {
        return $this->patterns;
    }

    /**
     * Get the number of patterns in the list.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->patterns);
    }

    /**
     * Check if the list is empty.
     *
     * @return bool
     */
    public function isEmpty(): bool
    {
        return empty($this->patterns);
    }

    /**
     * Get the name of this list.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Set a callback for persisting changes.
     *
     * @param callable $callback Function that receives (string $name, array $patterns).
     * @return self
     */
    public function onPersist(callable $callback): self
    {
        $this->persistCallback = $callback;

        return $this;
    }

    /**
     * Persist changes using the callback if set.
     */
    private function persist(): void
    {
        if ($this->persistCallback !== null) {
            ($this->persistCallback)($this->name, $this->patterns);
        }
    }

    /**
     * Create a list from an array.
     *
     * @param array<string> $patterns The patterns.
     * @param string $name The list name.
     * @return self
     */
    public static function fromArray(array $patterns, string $name = 'default'): self
    {
        return new self($name, $patterns);
    }

    /**
     * Create a list from a file (one pattern per line).
     *
     * @param string $filePath Path to the file.
     * @param string $name The list name.
     * @return self
     */
    public static function fromFile(string $filePath, string $name = 'default'): self
    {
        if (!file_exists($filePath)) {
            return new self($name);
        }

        $contents = file_get_contents($filePath);
        if ($contents === false) {
            return new self($name);
        }

        $lines = explode("\n", $contents);
        $patterns = [];

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip empty lines and comments
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $patterns[] = $line;
        }

        return new self($name, $patterns);
    }

    /**
     * Save the list to a file.
     *
     * @param string $filePath Path to the file.
     * @return bool True on success.
     */
    public function toFile(string $filePath): bool
    {
        $contents = "# IP List: {$this->name}\n";
        $contents .= '# Generated: ' . date('Y-m-d H:i:s') . "\n\n";
        $contents .= implode("\n", $this->patterns);

        return file_put_contents($filePath, $contents) !== false;
    }
}
