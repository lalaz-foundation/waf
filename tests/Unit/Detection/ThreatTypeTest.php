<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Detection;

use Lalaz\Waf\Detection\ThreatType;
use PHPUnit\Framework\TestCase;

class ThreatTypeTest extends TestCase
{
    public function test_xss_properties(): void
    {
        $type = ThreatType::XSS;

        $this->assertEquals('xss', $type->value);
        $this->assertEquals('Cross-Site Scripting (XSS)', $type->label());
        $this->assertEquals(7, $type->severity());
    }

    public function test_sql_injection_properties(): void
    {
        $type = ThreatType::SQL_INJECTION;

        $this->assertEquals('sql_injection', $type->value);
        $this->assertEquals('SQL Injection', $type->label());
        $this->assertEquals(10, $type->severity());
    }

    public function test_path_traversal_properties(): void
    {
        $type = ThreatType::PATH_TRAVERSAL;

        $this->assertEquals('path_traversal', $type->value);
        $this->assertEquals('Path Traversal', $type->label());
        $this->assertEquals(8, $type->severity());
    }

    public function test_command_injection_properties(): void
    {
        $type = ThreatType::COMMAND_INJECTION;

        $this->assertEquals('command_injection', $type->value);
        $this->assertEquals('Command Injection', $type->label());
        $this->assertEquals(10, $type->severity());
    }

    public function test_from_string(): void
    {
        $type = ThreatType::from('xss');

        $this->assertEquals(ThreatType::XSS, $type);
    }

    public function test_try_from_returns_null_for_invalid(): void
    {
        $type = ThreatType::tryFrom('invalid');

        $this->assertNull($type);
    }

    public function test_all_types_have_labels(): void
    {
        foreach (ThreatType::cases() as $type) {
            $this->assertNotEmpty($type->label());
        }
    }

    public function test_all_types_have_severity(): void
    {
        foreach (ThreatType::cases() as $type) {
            $severity = $type->severity();
            $this->assertGreaterThanOrEqual(1, $severity);
            $this->assertLessThanOrEqual(10, $severity);
        }
    }
}
