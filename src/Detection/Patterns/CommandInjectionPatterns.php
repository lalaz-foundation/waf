<?php

declare(strict_types=1);

namespace Lalaz\Waf\Detection\Patterns;

use Lalaz\Waf\Detection\ThreatType;

/**
 * Command Injection detection patterns.
 *
 * @package lalaz/waf
 */
final class CommandInjectionPatterns extends PatternSet
{
    public function getThreatType(): ThreatType
    {
        return ThreatType::COMMAND_INJECTION;
    }

    public function getPatterns(): array
    {
        return [
            // Command chaining
            'semicolon' => '/;\s*\w+/',
            'pipe' => '/\|\s*\w+/',
            'double_pipe' => '/\|\|\s*\w+/',
            'ampersand' => '/&\s*\w+/',
            'double_ampersand' => '/&&\s*\w+/',

            // Command substitution
            'backtick' => '/`[^`]+`/',
            'dollar_paren' => '/\$\([^)]+\)/',

            // Common dangerous commands
            'cat_command' => '/\bcat\s+/',
            'ls_command' => '/\bls\s+-/',
            'wget_command' => '/\bwget\s+/',
            'curl_command' => '/\bcurl\s+/',
            'nc_command' => '/\b(nc|netcat)\s+/',
            'bash_command' => '/\bbash\s+-/',
            'sh_command' => '/\bsh\s+-/',
            'python_command' => '/\bpython[23]?\s+-/',
            'perl_command' => '/\bperl\s+-/',
            'ruby_command' => '/\bruby\s+-/',
            'php_command' => '/\bphp\s+-/',

            // Dangerous executables
            'rm_command' => '/\brm\s+-/',
            'chmod_command' => '/\bchmod\s+/',
            'chown_command' => '/\bchown\s+/',
            'mv_command' => '/\bmv\s+/',
            'cp_command' => '/\bcp\s+/',

            // Network commands
            'ping_command' => '/\bping\s+-/',
            'nslookup_command' => '/\bnslookup\s+/',
            'dig_command' => '/\bdig\s+/',
            'telnet_command' => '/\btelnet\s+/',

            // System info
            'whoami_command' => '/\bwhoami\b/',
            'id_command' => '/\bid\b/',
            'uname_command' => '/\buname\s+-/',
            'hostname_command' => '/\bhostname\b/',
            'ifconfig_command' => '/\bifconfig\b/',
            'env_command' => '/\benv\b/',
            'printenv_command' => '/\bprintenv\b/',

            // File operations
            'touch_command' => '/\btouch\s+/',
            'mkdir_command' => '/\bmkdir\s+/',
            'echo_redirect' => '/\becho\s+.+>/',

            // Process manipulation
            'kill_command' => '/\bkill\s+-/',
            'pkill_command' => '/\bpkill\s+/',

            // Windows commands
            'cmd_exe' => '/\bcmd\s*\//',
            'powershell' => '/\bpowershell\b/i',
            'net_command' => '/\bnet\s+(user|localgroup|share)/i',
            'dir_command' => '/\bdir\s+\//',
            'type_command' => '/\btype\s+/',
            'copy_command' => '/\bcopy\s+/',
            'del_command' => '/\bdel\s+/',
            'reg_command' => '/\breg\s+(query|add|delete)/i',

            // Redirection
            'output_redirect' => '/>\s*\//',
            'append_redirect' => '/>>\s*/',
            'input_redirect' => '/<\s*\//',

            // Encoded payloads
            'base64_decode' => '/base64\s+-d/',
            'hex_decode' => '/xxd\s+-r/',

            // Environment variable injection
            'env_injection' => '/\$\{[^}]+\}/',
            'env_var' => '/\$[A-Z_][A-Z0-9_]*/i',
        ];
    }
}
