<?php

declare(strict_types=1);

namespace Lalaz\Waf\Detection;

use Lalaz\Waf\Detection\Patterns\CommandInjectionPatterns;
use Lalaz\Waf\Detection\Patterns\PathTraversalPatterns;
use Lalaz\Waf\Detection\Patterns\PatternSet;
use Lalaz\Waf\Detection\Patterns\SqlInjectionPatterns;
use Lalaz\Waf\Detection\Patterns\XssPatterns;

/**
 * Threat Detector
 *
 * Detects malicious patterns in input data including XSS, SQL Injection,
 * Path Traversal, and Command Injection.
 *
 * @package lalaz/waf
 */
final class ThreatDetector
{
    /**
     * @var array<PatternSet> Active pattern sets.
     */
    private array $patternSets = [];

    /**
     * @var array<string> Fields to exclude from scanning.
     */
    private array $excludedFields = [];

    /**
     * @var array<string> Fields containing HTML that need special handling.
     */
    private array $htmlFields = [];

    /**
     * @var int Maximum depth for recursive scanning.
     */
    private int $maxDepth = 10;

    /**
     * @var int Maximum string length to scan.
     */
    private int $maxLength = 100000;

    /**
     * Create a new threat detector.
     *
     * @param bool $detectXss Enable XSS detection.
     * @param bool $detectSqlInjection Enable SQL injection detection.
     * @param bool $detectPathTraversal Enable path traversal detection.
     * @param bool $detectCommandInjection Enable command injection detection.
     */
    public function __construct(
        bool $detectXss = true,
        bool $detectSqlInjection = true,
        bool $detectPathTraversal = true,
        bool $detectCommandInjection = true,
    ) {
        if ($detectXss) {
            $this->patternSets[] = new XssPatterns();
        }
        if ($detectSqlInjection) {
            $this->patternSets[] = new SqlInjectionPatterns();
        }
        if ($detectPathTraversal) {
            $this->patternSets[] = new PathTraversalPatterns();
        }
        if ($detectCommandInjection) {
            $this->patternSets[] = new CommandInjectionPatterns();
        }
    }

    /**
     * Scan a value for threats.
     *
     * @param mixed $value The value to scan.
     * @param string $location The location (e.g., 'body', 'query', 'headers').
     * @param string|null $field The field name.
     * @return array<Threat> Detected threats.
     */
    public function scan(mixed $value, string $location = 'input', ?string $field = null): array
    {
        return $this->scanValue($value, $location, $field, 0);
    }

    /**
     * Scan multiple values.
     *
     * @param array<string, mixed> $data
     * @param string $location
     * @return array<Threat>
     */
    public function scanArray(array $data, string $location = 'input'): array
    {
        $threats = [];

        foreach ($data as $field => $value) {
            $threats = array_merge($threats, $this->scan($value, $location, (string) $field));
        }

        return $threats;
    }

    /**
     * Check if a value contains any threats.
     *
     * @param mixed $value
     * @return bool
     */
    public function hasThreat(mixed $value): bool
    {
        return count($this->scan($value)) > 0;
    }

    /**
     * Scan a value recursively.
     *
     * @param mixed $value
     * @param string $location
     * @param string|null $field
     * @param int $depth
     * @return array<Threat>
     */
    private function scanValue(mixed $value, string $location, ?string $field, int $depth): array
    {
        // Prevent infinite recursion
        if ($depth > $this->maxDepth) {
            return [];
        }

        // Skip excluded fields
        if ($field !== null && in_array($field, $this->excludedFields, true)) {
            return [];
        }

        // Handle different types
        if (is_string($value)) {
            return $this->scanString($value, $location, $field);
        }

        if (is_array($value)) {
            $threats = [];
            foreach ($value as $key => $item) {
                $subField = $field !== null ? "{$field}.{$key}" : (string) $key;
                $threats = array_merge($threats, $this->scanValue($item, $location, $subField, $depth + 1));
            }
            return $threats;
        }

        if (is_object($value)) {
            return $this->scanValue((array) $value, $location, $field, $depth + 1);
        }

        return [];
    }

    /**
     * Scan a string value.
     *
     * @param string $value
     * @param string $location
     * @param string|null $field
     * @return array<Threat>
     */
    private function scanString(string $value, string $location, ?string $field): array
    {
        // Skip empty values
        if ($value === '') {
            return [];
        }

        // Truncate very long strings
        if (strlen($value) > $this->maxLength) {
            $value = substr($value, 0, $this->maxLength);
        }

        // Decode value for better detection
        $decodedValue = $this->decodeValue($value);

        $threats = [];

        foreach ($this->patternSets as $patternSet) {
            // Skip XSS for HTML fields (they need different handling)
            if ($patternSet->getThreatType() === ThreatType::XSS
                && $field !== null
                && in_array($field, $this->htmlFields, true)
            ) {
                continue;
            }

            // Check original value
            $result = $patternSet->match($value);
            if ($result['matched']) {
                $threats[] = new Threat(
                    type: $patternSet->getThreatType(),
                    payload: $this->truncatePayload($value),
                    location: $location,
                    pattern: $result['name'] ?? '',
                    field: $field,
                );
                continue; // Move to next pattern set
            }

            // Check decoded value
            if ($decodedValue !== $value) {
                $result = $patternSet->match($decodedValue);
                if ($result['matched']) {
                    $threats[] = new Threat(
                        type: $patternSet->getThreatType(),
                        payload: $this->truncatePayload($value),
                        location: $location,
                        pattern: $result['name'] ?? '',
                        field: $field,
                    );
                }
            }
        }

        return $threats;
    }

    /**
     * Decode a value (URL decode, HTML entities, etc.).
     */
    private function decodeValue(string $value): string
    {
        // Multiple rounds of URL decoding
        $decoded = $value;
        $prev = '';

        for ($i = 0; $i < 3 && $decoded !== $prev; $i++) {
            $prev = $decoded;
            $decoded = urldecode($decoded);
        }

        // HTML entity decoding
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Unicode escape sequences
        $decoded = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function ($matches) {
            return mb_convert_encoding(pack('H*', $matches[1]), 'UTF-8', 'UTF-16BE');
        }, $decoded) ?? $decoded;

        return $decoded;
    }

    /**
     * Truncate payload for storage/logging.
     */
    private function truncatePayload(string $payload, int $maxLength = 200): string
    {
        if (strlen($payload) <= $maxLength) {
            return $payload;
        }

        return substr($payload, 0, $maxLength) . '...';
    }

    /**
     * Add a custom pattern set.
     *
     * @param PatternSet $patternSet
     * @return self
     */
    public function addPatternSet(PatternSet $patternSet): self
    {
        $this->patternSets[] = $patternSet;
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
        $this->excludedFields = array_merge($this->excludedFields, $fields);
        return $this;
    }

    /**
     * Mark fields as HTML fields (skip XSS for these).
     *
     * @param array<string> $fields
     * @return self
     */
    public function htmlFields(array $fields): self
    {
        $this->htmlFields = array_merge($this->htmlFields, $fields);
        return $this;
    }

    /**
     * Set maximum recursion depth.
     *
     * @param int $depth
     * @return self
     */
    public function setMaxDepth(int $depth): self
    {
        $this->maxDepth = $depth;
        return $this;
    }

    /**
     * Set maximum string length to scan.
     *
     * @param int $length
     * @return self
     */
    public function setMaxLength(int $length): self
    {
        $this->maxLength = $length;
        return $this;
    }

    /**
     * Create a detector for XSS only.
     */
    public static function xssOnly(): self
    {
        return new self(
            detectXss: true,
            detectSqlInjection: false,
            detectPathTraversal: false,
            detectCommandInjection: false,
        );
    }

    /**
     * Create a detector for SQL Injection only.
     */
    public static function sqlInjectionOnly(): self
    {
        return new self(
            detectXss: false,
            detectSqlInjection: true,
            detectPathTraversal: false,
            detectCommandInjection: false,
        );
    }

    /**
     * Create a detector for Path Traversal only.
     */
    public static function pathTraversalOnly(): self
    {
        return new self(
            detectXss: false,
            detectSqlInjection: false,
            detectPathTraversal: true,
            detectCommandInjection: false,
        );
    }

    /**
     * Create a detector with all checks enabled.
     */
    public static function all(): self
    {
        return new self(
            detectXss: true,
            detectSqlInjection: true,
            detectPathTraversal: true,
            detectCommandInjection: true,
        );
    }

    /**
     * Create a detector from configuration.
     *
     * @param array<string, mixed> $config
     * @return self
     */
    public static function fromConfig(array $config): self
    {
        $detector = new self(
            detectXss: $config['detect_xss'] ?? true,
            detectSqlInjection: $config['detect_sql_injection'] ?? true,
            detectPathTraversal: $config['detect_path_traversal'] ?? true,
            detectCommandInjection: $config['detect_command_injection'] ?? true,
        );

        if (isset($config['excluded_fields'])) {
            $detector->excludeFields($config['excluded_fields']);
        }

        if (isset($config['html_fields'])) {
            $detector->htmlFields($config['html_fields']);
        }

        if (isset($config['max_depth'])) {
            $detector->setMaxDepth($config['max_depth']);
        }

        if (isset($config['max_length'])) {
            $detector->setMaxLength($config['max_length']);
        }

        return $detector;
    }
}
