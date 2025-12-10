<?php

declare(strict_types=1);

namespace Lalaz\Waf\Detection\Patterns;

use Lalaz\Waf\Detection\ThreatType;

/**
 * Base class for pattern sets used in threat detection.
 *
 * @package lalaz/waf
 */
abstract class PatternSet
{
    /**
     * Get the threat type this pattern set detects.
     */
    abstract public function getThreatType(): ThreatType;

    /**
     * Get all patterns.
     *
     * @return array<string, string> Pattern name => regex pattern
     */
    abstract public function getPatterns(): array;

    /**
     * Check if a value matches any pattern.
     *
     * @param string $value The value to check.
     * @return array{matched: bool, pattern: string|null, name: string|null}
     */
    public function match(string $value): array
    {
        foreach ($this->getPatterns() as $name => $pattern) {
            if (preg_match($pattern, $value)) {
                return [
                    'matched' => true,
                    'pattern' => $pattern,
                    'name' => $name,
                ];
            }
        }

        return [
            'matched' => false,
            'pattern' => null,
            'name' => null,
        ];
    }

    /**
     * Check if a value matches any pattern.
     */
    public function matches(string $value): bool
    {
        return $this->match($value)['matched'];
    }
}
