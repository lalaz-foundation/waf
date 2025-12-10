<?php

declare(strict_types=1);

namespace Lalaz\Waf\Detection;

/**
 * Enum representing types of threats detected by the WAF.
 *
 * @package lalaz/waf
 */
enum ThreatType: string
{
    case XSS = 'xss';
    case SQL_INJECTION = 'sql_injection';
    case PATH_TRAVERSAL = 'path_traversal';
    case COMMAND_INJECTION = 'command_injection';
    case LDAP_INJECTION = 'ldap_injection';
    case XML_INJECTION = 'xml_injection';
    case HEADER_INJECTION = 'header_injection';
    case NULL_BYTE = 'null_byte';

    /**
     * Get a human-readable label for the threat type.
     */
    public function label(): string
    {
        return match ($this) {
            self::XSS => 'Cross-Site Scripting (XSS)',
            self::SQL_INJECTION => 'SQL Injection',
            self::PATH_TRAVERSAL => 'Path Traversal',
            self::COMMAND_INJECTION => 'Command Injection',
            self::LDAP_INJECTION => 'LDAP Injection',
            self::XML_INJECTION => 'XML Injection',
            self::HEADER_INJECTION => 'Header Injection',
            self::NULL_BYTE => 'Null Byte Injection',
        };
    }

    /**
     * Get the severity level (1-10).
     */
    public function severity(): int
    {
        return match ($this) {
            self::SQL_INJECTION => 10,
            self::COMMAND_INJECTION => 10,
            self::PATH_TRAVERSAL => 8,
            self::XSS => 7,
            self::LDAP_INJECTION => 8,
            self::XML_INJECTION => 7,
            self::HEADER_INJECTION => 6,
            self::NULL_BYTE => 5,
        };
    }
}
