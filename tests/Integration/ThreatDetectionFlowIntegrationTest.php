<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Integration;

use Lalaz\Waf\Tests\Common\WafIntegrationTestCase;
use Lalaz\Waf\Detection\ThreatDetector;
use Lalaz\Waf\Detection\ThreatType;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Integration tests for complete threat detection flows.
 *
 * These tests verify the complete detection pipeline including:
 * - Multi-type threat detection
 * - Array/nested scanning
 * - Configuration-based detection
 * - Field exclusion and HTML field handling
 * - Edge cases and encoding handling
 *
 * @package lalaz/waf
 */
final class ThreatDetectionFlowIntegrationTest extends WafIntegrationTestCase
{
    // =========================================================================
    // Complete Detection Flow Tests
    // =========================================================================

    #[Test]
    public function it_detects_all_threat_types_in_mixed_payload(): void
    {
        $detector = ThreatDetector::all();

        $threats = $detector->scanArray([
            'comment' => '<script>alert("xss")</script>',
            'search' => "' OR 1=1--",
            'file' => '../../../etc/passwd',
            'cmd' => '; rm -rf /',
        ]);

        // Should detect at least 4 threats
        $this->assertGreaterThanOrEqual(4, count($threats));

        // Check for each threat type
        $types = array_map(fn($t) => $t->type->value, $threats);

        $this->assertContains('xss', $types);
        $this->assertContains('sql_injection', $types);
        $this->assertContains('path_traversal', $types);
        $this->assertContains('command_injection', $types);
    }

    #[Test]
    public function it_tracks_field_locations_in_nested_arrays(): void
    {
        $detector = ThreatDetector::xssOnly();

        $threats = $detector->scan([
            'user' => [
                'profile' => [
                    'bio' => '<script>alert(1)</script>',
                    'website' => 'https://safe.com',
                ],
                'settings' => [
                    'signature' => '<img onerror="alert(2)">',
                ],
            ],
        ]);

        $this->assertCount(2, $threats);

        $fields = array_map(fn($t) => $t->field, $threats);
        $this->assertContains('user.profile.bio', $fields);
        $this->assertContains('user.settings.signature', $fields);
    }

    #[Test]
    public function it_respects_excluded_fields(): void
    {
        $detector = ThreatDetector::all()
            ->excludeFields(['html_content', 'raw_html', 'signature']);

        $threats = $detector->scanArray([
            'html_content' => '<script>alert(1)</script>',
            'raw_html' => '<img onerror="alert(2)">',
            'signature' => "'; DROP TABLE users--",
            'user_input' => '<script>alert(3)</script>',
        ]);

        // Check that excluded fields are not in threat list
        $fields = array_map(fn($t) => $t->field, $threats);
        $this->assertNotContains('html_content', $fields);
        $this->assertNotContains('raw_html', $fields);
        $this->assertNotContains('signature', $fields);

        // user_input should still be detected
        $this->assertContains('user_input', $fields);
    }

    #[Test]
    public function it_handles_html_fields_correctly(): void
    {
        $detector = ThreatDetector::all()
            ->htmlFields(['content', 'body']);

        $threats = $detector->scanArray([
            'content' => '<script>alert(1)</script>', // HTML field - XSS skipped
            'body' => '<img onerror="alert(2)">',     // HTML field - XSS skipped
            'title' => '<script>alert(3)</script>',   // Normal field - flagged
        ]);

        // Only title XSS should be flagged (HTML fields skip XSS)
        $xssThreats = array_filter($threats, fn($t) => $t->type === ThreatType::XSS);
        $this->assertGreaterThanOrEqual(1, count($xssThreats));

        // Check that 'title' was flagged for XSS
        $xssFields = array_map(fn($t) => $t->field, $xssThreats);
        $this->assertContains('title', $xssFields);
    }

    // =========================================================================
    // Encoding and Evasion Tests
    // =========================================================================

    #[Test]
    #[DataProvider('encodedXssProvider')]
    public function it_detects_encoded_xss_payloads(string $payload): void
    {
        $this->assertXssDetected($payload);
    }

    public static function encodedXssProvider(): array
    {
        return [
            'URL encoded script tag' => ['%3Cscript%3Ealert(1)%3C/script%3E'],
            'Double URL encoded' => ['%253Cscript%253Ealert(1)%253C%252Fscript%253E'],
            'Mixed case' => ['<ScRiPt>alert(1)</sCrIpT>'],
            'With null bytes' => ["<script\x00>alert(1)</script>"],
            'HTML entity encoded' => ['&#60;script&#62;alert(1)&#60;/script&#62;'],
            'Onload event' => ['<body onload="alert(1)">'],
        ];
    }

    #[Test]
    #[DataProvider('encodedSqlInjectionProvider')]
    public function it_detects_encoded_sql_injection_payloads(string $payload): void
    {
        $this->assertSqlInjectionDetected($payload);
    }

    public static function encodedSqlInjectionProvider(): array
    {
        return [
            'Basic OR injection' => ["' OR '1'='1"],
            'Comment termination' => ["admin'--"],
            'UNION SELECT' => ['1 UNION SELECT * FROM users'],
            'Double quote' => ['" OR "1"="1'],
            'With semicolon' => ["'; DROP TABLE users;--"],
            'Boolean-based' => ["1' AND '1'='1"],
        ];
    }

    #[Test]
    #[DataProvider('encodedPathTraversalProvider')]
    public function it_detects_encoded_path_traversal_payloads(string $payload): void
    {
        $this->assertPathTraversalDetected($payload);
    }

    public static function encodedPathTraversalProvider(): array
    {
        return [
            'Basic traversal' => ['../../../etc/passwd'],
            'URL encoded' => ['%2e%2e%2f%2e%2e%2fetc/passwd'],
            'Double encoded' => ['%252e%252e%252fetc/passwd'],
            'Windows style' => ['..\\..\\..\\windows\\system32\\config\\sam'],
            'Null byte' => ['../../../etc/passwd%00.jpg'],
            'Deep traversal' => ['..............//etc/passwd'],
        ];
    }

    // =========================================================================
    // Configuration-Based Detection Tests
    // =========================================================================

    #[Test]
    public function it_creates_detector_from_config(): void
    {
        $detector = ThreatDetector::fromConfig([
            'detect_xss' => true,
            'detect_sql_injection' => true,
            'detect_path_traversal' => false,
            'detect_command_injection' => false,
            'excluded_fields' => ['signature'],
            'html_fields' => ['body'],
        ]);

        // XSS should be detected
        $this->assertTrue($detector->hasThreat('<script>alert(1)</script>'));

        // SQL Injection should be detected
        $this->assertTrue($detector->hasThreat("' OR 1=1--"));

        // Path Traversal should NOT be detected (disabled)
        $this->assertFalse($detector->hasThreat('../etc/passwd'));

        // Command Injection should NOT be detected (disabled)
        $this->assertFalse($detector->hasThreat('; ls -la'));
    }

    #[Test]
    public function it_chains_configuration_methods_fluently(): void
    {
        $detector = ThreatDetector::all()
            ->excludeFields(['safe_field'])
            ->htmlFields(['html_body'])
            ->setMaxLength(100)
            ->setMaxDepth(5);

        $this->assertInstanceOf(ThreatDetector::class, $detector);
    }

    // =========================================================================
    // Edge Cases Tests
    // =========================================================================

    #[Test]
    public function it_handles_empty_and_null_values_gracefully(): void
    {
        $detector = ThreatDetector::all();

        $this->assertEmpty($detector->scan(''));
        $this->assertEmpty($detector->scan(null));
        $this->assertEmpty($detector->scanArray([]));
        $this->assertEmpty($detector->scanArray(['key' => '']));
        $this->assertEmpty($detector->scanArray(['key' => null]));
    }

    #[Test]
    public function it_handles_numeric_values(): void
    {
        $detector = ThreatDetector::all();

        $this->assertEmpty($detector->scan(123));
        $this->assertEmpty($detector->scan(45.67));
        $this->assertEmpty($detector->scanArray(['id' => 123, 'price' => 45.67]));
    }

    #[Test]
    public function it_handles_very_long_payloads(): void
    {
        $detector = ThreatDetector::xssOnly();

        // Very long payload with XSS at the beginning
        $longPayload = '<script>alert(1)</script>' . str_repeat('x', 10000);
        $threats = $detector->scan($longPayload);

        $this->assertNotEmpty($threats);

        // Payload should be truncated in the threat record
        $this->assertLessThan(500, strlen($threats[0]->payload));
    }

    #[Test]
    public function it_handles_unicode_payloads(): void
    {
        $detector = ThreatDetector::all();

        // Unicode with XSS
        $threats = $detector->scan('<script>alert("日本語")</script>');
        $this->assertNotEmpty($threats);

        // Safe unicode
        $this->assertEmpty($detector->scan('日本語テスト'));
        $this->assertEmpty($detector->scan('🔐🚀 Emojis are safe'));
    }

    // =========================================================================
    // False Positive Tests
    // =========================================================================

    #[Test]
    #[DataProvider('safePayloadsProvider')]
    public function it_does_not_flag_safe_payloads(string $payload): void
    {
        $this->assertPayloadIsSafe($payload);
    }

    public static function safePayloadsProvider(): array
    {
        return [
            'Simple text' => ['Hello, World!'],
            'Email address' => ['user@example.com'],
            'Product description' => ['This product is great! 5 stars.'],
            'File path mention' => ['The config file is at /app/config.json'],
            'JSON-like' => ['{"name": "John", "age": 30}'],
            'Math expression' => ['Calculate: 1 + 1 = 2'],
        ];
    }

    // =========================================================================
    // Severity Tests
    // =========================================================================

    #[Test]
    public function it_assigns_correct_severity_to_threats(): void
    {
        $this->assertEquals(7, ThreatType::XSS->severity());
        $this->assertEquals(10, ThreatType::SQL_INJECTION->severity());
        $this->assertEquals(8, ThreatType::PATH_TRAVERSAL->severity());
        $this->assertEquals(10, ThreatType::COMMAND_INJECTION->severity());
    }

    #[Test]
    public function it_provides_human_readable_labels(): void
    {
        $this->assertEquals('Cross-Site Scripting (XSS)', ThreatType::XSS->label());
        $this->assertEquals('SQL Injection', ThreatType::SQL_INJECTION->label());
        $this->assertEquals('Path Traversal', ThreatType::PATH_TRAVERSAL->label());
        $this->assertEquals('Command Injection', ThreatType::COMMAND_INJECTION->label());
    }
}
