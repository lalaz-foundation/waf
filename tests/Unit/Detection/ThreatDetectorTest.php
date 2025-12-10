<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Detection;

use Lalaz\Waf\Detection\ThreatDetector;
use Lalaz\Waf\Detection\ThreatType;
use PHPUnit\Framework\TestCase;

class ThreatDetectorTest extends TestCase
{
    // ========================================
    // XSS Detection Tests
    // ========================================

    public function test_detects_script_tag(): void
    {
        $detector = ThreatDetector::xssOnly();
        $threats = $detector->scan('<script>alert("xss")</script>');

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::XSS, $threats[0]->type);
    }

    public function test_detects_event_handler(): void
    {
        $detector = ThreatDetector::xssOnly();
        $threats = $detector->scan('<img src=x onerror="alert(1)">');

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::XSS, $threats[0]->type);
    }

    public function test_detects_javascript_protocol(): void
    {
        $detector = ThreatDetector::xssOnly();
        $threats = $detector->scan('<a href="javascript:alert(1)">click</a>');

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::XSS, $threats[0]->type);
    }

    public function test_detects_svg_xss(): void
    {
        $detector = ThreatDetector::xssOnly();
        $threats = $detector->scan('<svg onload="alert(1)">');

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::XSS, $threats[0]->type);
    }

    public function test_detects_iframe(): void
    {
        $detector = ThreatDetector::xssOnly();
        $threats = $detector->scan('<iframe src="evil.com">');

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::XSS, $threats[0]->type);
    }

    public function test_detects_encoded_xss(): void
    {
        $detector = ThreatDetector::xssOnly();
        // URL encoded <script>
        $threats = $detector->scan('%3Cscript%3Ealert(1)%3C/script%3E');

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::XSS, $threats[0]->type);
    }

    // ========================================
    // SQL Injection Detection Tests
    // ========================================

    public function test_detects_union_select(): void
    {
        $detector = ThreatDetector::sqlInjectionOnly();
        $threats = $detector->scan("1 UNION SELECT * FROM users");

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::SQL_INJECTION, $threats[0]->type);
    }

    public function test_detects_or_true(): void
    {
        $detector = ThreatDetector::sqlInjectionOnly();
        $threats = $detector->scan("' OR '1'='1");

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::SQL_INJECTION, $threats[0]->type);
    }

    public function test_detects_comment_termination(): void
    {
        $detector = ThreatDetector::sqlInjectionOnly();
        $threats = $detector->scan("admin'--");

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::SQL_INJECTION, $threats[0]->type);
    }

    public function test_detects_sleep_injection(): void
    {
        $detector = ThreatDetector::sqlInjectionOnly();
        $threats = $detector->scan("1; SLEEP(5)");

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::SQL_INJECTION, $threats[0]->type);
    }

    public function test_detects_drop_table(): void
    {
        $detector = ThreatDetector::sqlInjectionOnly();
        $threats = $detector->scan("1; DROP TABLE users");

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::SQL_INJECTION, $threats[0]->type);
    }

    public function test_detects_information_schema(): void
    {
        $detector = ThreatDetector::sqlInjectionOnly();
        $threats = $detector->scan("1 UNION SELECT * FROM information_schema.tables");

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::SQL_INJECTION, $threats[0]->type);
    }

    // ========================================
    // Path Traversal Detection Tests
    // ========================================

    public function test_detects_dot_dot_slash(): void
    {
        $detector = ThreatDetector::pathTraversalOnly();
        $threats = $detector->scan('../../../etc/passwd');

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::PATH_TRAVERSAL, $threats[0]->type);
    }

    public function test_detects_encoded_dot_dot_slash(): void
    {
        $detector = ThreatDetector::pathTraversalOnly();
        $threats = $detector->scan('%2e%2e%2f%2e%2e%2fetc/passwd');

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::PATH_TRAVERSAL, $threats[0]->type);
    }

    public function test_detects_null_byte(): void
    {
        $detector = ThreatDetector::pathTraversalOnly();
        $threats = $detector->scan("image.jpg%00.php");

        $this->assertCount(1, $threats);
        $this->assertEquals(ThreatType::PATH_TRAVERSAL, $threats[0]->type);
    }

    public function test_detects_sensitive_files(): void
    {
        $detector = ThreatDetector::pathTraversalOnly();

        $this->assertNotEmpty($detector->scan('/etc/passwd'));
        $this->assertNotEmpty($detector->scan('.htaccess'));
        $this->assertNotEmpty($detector->scan('.git/config'));
        $this->assertNotEmpty($detector->scan('.env'));
    }

    // ========================================
    // Array Scanning Tests
    // ========================================

    public function test_scans_array_values(): void
    {
        $detector = ThreatDetector::all();

        $threats = $detector->scanArray([
            'name' => 'John',
            'comment' => '<script>alert(1)</script>',
            'id' => "1 OR 1=1",
        ]);

        // At least 2 threats (XSS and SQL Injection), possibly more patterns match
        $this->assertGreaterThanOrEqual(2, count($threats));

        // Verify we detected both types
        $types = array_map(fn($t) => $t->type, $threats);
        $hasXss = in_array(ThreatType::XSS, $types, true);
        $hasSqlInjection = in_array(ThreatType::SQL_INJECTION, $types, true);

        $this->assertTrue($hasXss, 'Should detect XSS');
        $this->assertTrue($hasSqlInjection, 'Should detect SQL Injection');
    }

    public function test_scans_nested_arrays(): void
    {
        $detector = ThreatDetector::xssOnly();

        $threats = $detector->scan([
            'user' => [
                'profile' => [
                    'bio' => '<script>alert(1)</script>',
                ],
            ],
        ]);

        $this->assertCount(1, $threats);
        $this->assertStringContainsString('user.profile.bio', $threats[0]->field);
    }

    public function test_records_field_location(): void
    {
        $detector = ThreatDetector::xssOnly();
        $threats = $detector->scan('<script>alert(1)</script>', 'body', 'comment');

        $this->assertEquals('body', $threats[0]->location);
        $this->assertEquals('comment', $threats[0]->field);
    }

    // ========================================
    // Configuration Tests
    // ========================================

    public function test_exclude_fields(): void
    {
        $detector = ThreatDetector::xssOnly()
            ->excludeFields(['html_content']);

        $threats = $detector->scanArray([
            'html_content' => '<script>alert(1)</script>',
            'comment' => '<script>alert(2)</script>',
        ]);

        $this->assertCount(1, $threats);
        $this->assertEquals('comment', $threats[0]->field);
    }

    public function test_html_fields_skip_xss(): void
    {
        $detector = ThreatDetector::all()
            ->htmlFields(['content']);

        $threats = $detector->scanArray([
            'content' => '<script>alert(1)</script>',
            'title' => '<script>alert(2)</script>',
        ]);

        // Only title should be flagged (content is HTML field)
        $xssThreats = array_filter($threats, fn($t) => $t->type === ThreatType::XSS);
        $this->assertCount(1, $xssThreats);
    }

    public function test_has_threat(): void
    {
        $detector = ThreatDetector::xssOnly();

        $this->assertTrue($detector->hasThreat('<script>alert(1)</script>'));
        $this->assertFalse($detector->hasThreat('Hello World'));
    }

    // ========================================
    // Factory Methods Tests
    // ========================================

    public function test_all_factory(): void
    {
        $detector = ThreatDetector::all();

        $this->assertTrue($detector->hasThreat('<script>alert(1)</script>'));
        $this->assertTrue($detector->hasThreat("' OR 1=1--"));
        $this->assertTrue($detector->hasThreat('../etc/passwd'));
    }

    public function test_from_config(): void
    {
        $detector = ThreatDetector::fromConfig([
            'detect_xss' => true,
            'detect_sql_injection' => false,
            'detect_path_traversal' => false,
            'detect_command_injection' => false,
            'excluded_fields' => ['ignore_me'],
        ]);

        $this->assertTrue($detector->hasThreat('<script>alert(1)</script>'));
        $this->assertFalse($detector->hasThreat("' OR 1=1--"));
    }

    // ========================================
    // Edge Cases
    // ========================================

    public function test_handles_empty_string(): void
    {
        $detector = ThreatDetector::all();
        $threats = $detector->scan('');

        $this->assertEmpty($threats);
    }

    public function test_handles_null_value(): void
    {
        $detector = ThreatDetector::all();
        $threats = $detector->scan(null);

        $this->assertEmpty($threats);
    }

    public function test_handles_numeric_values(): void
    {
        $detector = ThreatDetector::all();

        $this->assertEmpty($detector->scan(123));
        $this->assertEmpty($detector->scan(45.67));
    }

    public function test_safe_values_pass(): void
    {
        $detector = ThreatDetector::all();

        $this->assertEmpty($detector->scan('John Doe'));
        $this->assertEmpty($detector->scan('john@example.com'));
        $this->assertEmpty($detector->scan('Hello, how are you?'));
        $this->assertEmpty($detector->scan('Product #123'));
    }

    public function test_truncates_long_payloads(): void
    {
        $detector = ThreatDetector::xssOnly();
        $longPayload = '<script>' . str_repeat('x', 500) . '</script>';

        $threats = $detector->scan($longPayload);

        $this->assertNotEmpty($threats);
        $this->assertLessThan(300, strlen($threats[0]->payload));
    }
}
