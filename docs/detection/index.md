# Threat Detection

Detect XSS, SQL Injection, Path Traversal, and Command Injection.

---

## Overview

The threat detection module scans input data for known attack patterns and returns detailed information about detected threats.

## Quick Start

```php
use Lalaz\Waf\Detection\ThreatDetector;

$detector = ThreatDetector::all();

$threats = $detector->scan('<script>alert("xss")</script>');

if (!empty($threats)) {
    foreach ($threats as $threat) {
        echo "Detected: {$threat->type()->label()}\n";
        echo "Severity: {$threat->type()->severity()}\n";
        echo "Matched: {$threat->matchedValue()}\n";
    }
}
```

## ThreatDetector

### Factory Methods

```php
use Lalaz\Waf\Detection\ThreatDetector;

// Detect all threat types
$detector = ThreatDetector::all();

// XSS only
$detector = ThreatDetector::xssOnly();

// SQL Injection only
$detector = ThreatDetector::sqlInjectionOnly();

// Path Traversal only
$detector = ThreatDetector::pathTraversalOnly();

// From configuration array
$detector = ThreatDetector::fromConfig([
    'xss' => true,
    'sql_injection' => true,
    'path_traversal' => false,
    'command_injection' => false,
]);
```

### Methods

#### `scan(string $input): array`

Scan input for threats. Returns an array of `Threat` objects.

```php
$threats = $detector->scan($_POST['comment']);
```

#### `scanArray(array $data): array`

Scan all values in an array recursively.

```php
$threats = $detector->scanArray($_POST);
```

#### `isClean(string $input): bool`

Check if input is free of threats.

```php
if ($detector->isClean($input)) {
    // Safe to process
}
```

## ThreatType

The `ThreatType` enum represents different attack types:

```php
use Lalaz\Waf\Detection\ThreatType;

ThreatType::XSS;
ThreatType::SQL_INJECTION;
ThreatType::PATH_TRAVERSAL;
ThreatType::COMMAND_INJECTION;
```

### Methods

```php
// Human-readable label
ThreatType::XSS->label(); // "Cross-Site Scripting"

// Severity (1-10)
ThreatType::XSS->severity();              // 8
ThreatType::SQL_INJECTION->severity();    // 9
ThreatType::PATH_TRAVERSAL->severity();   // 7
ThreatType::COMMAND_INJECTION->severity(); // 10
```

## Threat

The `Threat` value object represents a detected threat:

```php
use Lalaz\Waf\Detection\Threat;

$threat = new Threat(
    type: ThreatType::XSS,
    pattern: '/<script/i',
    matchedValue: '<script>alert("xss")'
);

$threat->type();         // ThreatType::XSS
$threat->pattern();      // '/<script/i'
$threat->matchedValue(); // '<script>alert("xss")'
```

## Pattern Sets

Each threat type has a dedicated pattern set:

### XSS Patterns

```php
use Lalaz\Waf\Detection\Patterns\XssPatterns;

$patterns = XssPatterns::getPatterns();
// Detects:
// - <script> tags
// - javascript: URLs
// - Event handlers (onclick, onerror, etc.)
// - Data URLs
// - SVG/object/embed injection
// - Expression() in CSS
```

### SQL Injection Patterns

```php
use Lalaz\Waf\Detection\Patterns\SqlInjectionPatterns;

$patterns = SqlInjectionPatterns::getPatterns();
// Detects:
// - UNION SELECT
// - OR 1=1
// - Comment sequences (--, /*, #)
// - SLEEP(), BENCHMARK()
// - CHAR(), CONCAT() abuse
// - Stacked queries (;)
```

### Path Traversal Patterns

```php
use Lalaz\Waf\Detection\Patterns\PathTraversalPatterns;

$patterns = PathTraversalPatterns::getPatterns();
// Detects:
// - ../ sequences
// - Encoded variants (%2e%2e, etc.)
// - Null bytes
// - /etc/passwd, /etc/shadow
// - Windows paths (C:\, \\server\)
```

### Command Injection Patterns

```php
use Lalaz\Waf\Detection\Patterns\CommandInjectionPatterns;

$patterns = CommandInjectionPatterns::getPatterns();
// Detects:
// - Shell metacharacters (;, |, &, `, $())
// - Common commands (cat, ls, whoami, etc.)
// - Encoded variants
// - Backticks
```

## Custom Patterns

Create custom pattern sets by extending `PatternSet`:

```php
use Lalaz\Waf\Detection\Patterns\PatternSet;
use Lalaz\Waf\Detection\ThreatType;

class CustomPatterns extends PatternSet
{
    protected static function patterns(): array
    {
        return [
            '/malicious_pattern/i',
            '/another_pattern/i',
        ];
    }
    
    protected static function threatType(): ThreatType
    {
        return ThreatType::CUSTOM; // Would need to extend ThreatType
    }
}
```

## SanitizationMiddleware

Use the middleware for automatic threat detection:

```php
use Lalaz\Waf\Middlewares\SanitizationMiddleware;

// Block all threats (recommended for production)
$middleware = SanitizationMiddleware::strict();

// Log threats but don't block (monitoring mode)
$middleware = SanitizationMiddleware::logOnly();

// Basic sanitization (HTML entities)
$middleware = SanitizationMiddleware::basic();

// API mode (JSON-aware)
$middleware = SanitizationMiddleware::forApi();
```

### Custom Configuration

```php
$middleware = new SanitizationMiddleware(
    detector: ThreatDetector::all(),
    mode: 'block', // 'block', 'log', 'sanitize'
    logger: $logger,
    excludedPaths: ['/webhooks/*'],
    excludedParams: ['signature', 'token'],
);
```

## Example: Form Validation

```php
use Lalaz\Waf\Detection\ThreatDetector;

class CommentController
{
    private ThreatDetector $detector;
    
    public function __construct()
    {
        $this->detector = ThreatDetector::all();
    }
    
    public function store(Request $request): Response
    {
        $comment = $request->input('comment');
        
        $threats = $this->detector->scan($comment);
        
        if (!empty($threats)) {
            $this->logThreats($threats, $request);
            return response()->json([
                'error' => 'Invalid content detected',
            ], 400);
        }
        
        // Safe to store
        Comment::create(['body' => $comment]);
        
        return response()->json(['status' => 'created'], 201);
    }
    
    private function logThreats(array $threats, Request $request): void
    {
        foreach ($threats as $threat) {
            Log::warning('Threat detected', [
                'type' => $threat->type()->label(),
                'severity' => $threat->type()->severity(),
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]);
        }
    }
}
```

## Best Practices

1. **Use `ThreatDetector::all()` by default** for comprehensive protection
2. **Log all detected threats** for security monitoring
3. **Don't expose pattern details** to users (security through obscurity)
4. **Combine with other defenses** (parameterized queries, output encoding)
5. **Review false positives** and adjust patterns as needed

## Next Steps

- [IP Filtering](../ip-filter/index.md) — Filter by IP address
- [Rate Limiting](../rate-limit/index.md) — Request rate limiting
- [Middlewares](../middlewares/index.md) — All available middlewares
