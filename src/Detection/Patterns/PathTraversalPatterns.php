<?php

declare(strict_types=1);

namespace Lalaz\Waf\Detection\Patterns;

use Lalaz\Waf\Detection\ThreatType;

/**
 * Path Traversal detection patterns.
 *
 * @package lalaz/waf
 */
final class PathTraversalPatterns extends PatternSet
{
    public function getThreatType(): ThreatType
    {
        return ThreatType::PATH_TRAVERSAL;
    }

    public function getPatterns(): array
    {
        return [
            // Basic traversal
            'dot_dot_slash' => '/\.\.\//',
            'dot_dot_backslash' => '/\.\.\\\/',

            // URL encoded
            'encoded_dot_dot_slash' => '/%2e%2e%2f/i',
            'encoded_dot_dot_backslash' => '/%2e%2e%5c/i',
            'partial_encoded_1' => '/%2e\.\//',
            'partial_encoded_2' => '/\.%2e\//',
            'partial_encoded_3' => '/%2e%2e\//',
            'partial_encoded_4' => '/\.\.%2f/i',

            // Double URL encoded
            'double_encoded_slash' => '/%252e%252e%252f/i',
            'double_encoded_backslash' => '/%252e%252e%255c/i',

            // Unicode/overlong UTF-8 encoding
            'overlong_utf8' => '/%c0%ae/i',
            'overlong_utf8_2' => '/%c0%2e/i',
            'overlong_slash' => '/%c0%af/i',
            'overlong_backslash' => '/%c1%9c/i',

            // 16-bit Unicode encoding
            'unicode_dot' => '/%u002e/i',
            'unicode_slash' => '/%u2215/i',
            'unicode_backslash' => '/%u2216/i',

            // Null byte injection (for bypassing extension checks)
            'null_byte' => '/%00/',
            'null_byte_hex' => '/\x00/',

            // Windows-specific
            'windows_device' => '/(?:^|[\\/])(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:[\\/\.]|$)/i',
            'unc_path' => '/^\\\\\\\\[^\\\\]+\\\\/', // UNC path \\server\share

            // Absolute paths
            'unix_root' => '/^\/etc\/|^\/var\/|^\/usr\/|^\/home\/|^\/root\//i',
            'windows_root' => '/^[a-z]:\\\\/i',

            // Common sensitive files
            'passwd_file' => '/\/etc\/passwd/i',
            'shadow_file' => '/\/etc\/shadow/i',
            'hosts_file' => '/\/etc\/hosts/i',
            'bashrc_file' => '/\.bashrc/i',
            'ssh_keys' => '/\.ssh\/(id_rsa|authorized_keys)/i',
            'htpasswd' => '/\.htpasswd/i',
            'htaccess' => '/\.htaccess/i',
            'git_config' => '/\.git\/(config|HEAD)/i',
            'env_file' => '/\.env/i',
            'config_php' => '/config\.php/i',
            'wp_config' => '/wp-config\.php/i',

            // Windows sensitive files
            'win_ini' => '/boot\.ini|win\.ini|system\.ini/i',
            'sam_file' => '/windows\/system32\/config\/sam/i',

            // Tomcat specific
            'tomcat_users' => '/tomcat-users\.xml/i',
            'web_xml' => '/WEB-INF\/web\.xml/i',

            // Java specific
            'java_class' => '/\.class$/i',
            'jar_file' => '/\.jar$/i',

            // Server logs
            'access_log' => '/access[_\-]?log/i',
            'error_log' => '/error[_\-]?log/i',

            // Backup files
            'backup_extension' => '/\.(bak|backup|old|orig|save|swp|tmp)$/i',
            'tilde_backup' => '/~$/i',
        ];
    }
}
