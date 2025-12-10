<?php declare(strict_types=1);

namespace Lalaz\Waf\Tests\Unit\Detection;

use Lalaz\Waf\Detection\ThreatType;
use Lalaz\Waf\Detection\Threat;
use PHPUnit\Framework\TestCase;

class ThreatTest extends TestCase
{
    public function test_creates_threat(): void
    {
        $threat = new Threat(
            type: ThreatType::XSS,
            payload: '<script>alert(1)</script>',
            location: 'body',
            pattern: 'script_tag',
            field: 'comment',
        );

        $this->assertEquals(ThreatType::XSS, $threat->type);
        $this->assertEquals('<script>alert(1)</script>', $threat->payload);
        $this->assertEquals('body', $threat->location);
        $this->assertEquals('script_tag', $threat->pattern);
        $this->assertEquals('comment', $threat->field);
    }

    public function test_to_array(): void
    {
        $threat = new Threat(
            type: ThreatType::SQL_INJECTION,
            payload: "' OR 1=1--",
            location: 'query',
            pattern: 'or_true',
            field: 'id',
        );

        $array = $threat->toArray();

        $this->assertEquals('sql_injection', $array['type']);
        $this->assertEquals('SQL Injection', $array['label']);
        $this->assertEquals(10, $array['severity']);
        $this->assertEquals("' OR 1=1--", $array['payload']);
        $this->assertEquals('query', $array['location']);
        $this->assertEquals('id', $array['field']);
        $this->assertEquals('or_true', $array['pattern']);
    }

    public function test_from_array(): void
    {
        $data = [
            'type' => 'path_traversal',
            'payload' => '../../../etc/passwd',
            'location' => 'path',
            'pattern' => 'dot_dot_slash',
            'field' => 'file',
        ];

        $threat = Threat::fromArray($data);

        $this->assertEquals(ThreatType::PATH_TRAVERSAL, $threat->type);
        $this->assertEquals('../../../etc/passwd', $threat->payload);
        $this->assertEquals('path', $threat->location);
        $this->assertEquals('dot_dot_slash', $threat->pattern);
        $this->assertEquals('file', $threat->field);
    }
}
