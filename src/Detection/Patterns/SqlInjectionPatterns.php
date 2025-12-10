<?php

declare(strict_types=1);

namespace Lalaz\Waf\Detection\Patterns;

use Lalaz\Waf\Detection\ThreatType;

/**
 * SQL Injection detection patterns.
 *
 * @package lalaz/waf
 */
final class SqlInjectionPatterns extends PatternSet
{
    public function getThreatType(): ThreatType
    {
        return ThreatType::SQL_INJECTION;
    }

    public function getPatterns(): array
    {
        return [
            // Union-based injection
            'union_select' => '/\bunion\b[\s\S]*?\bselect\b/i',
            'union_all' => '/\bunion\s+all\s+select\b/i',

            // Comment-based termination
            'comment_dash' => '/--\s*$/m',
            'comment_hash' => '/#\s*$/m',
            'comment_block' => '/\/\*[\s\S]*?\*\//i',

            // Boolean-based blind
            'or_true' => '/\bor\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?/i',
            'and_true' => '/\band\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?/i',
            'or_string' => '/\bor\b\s+[\'\"][^\'\"]*[\'\"]\s*=\s*[\'\"][^\'\"]*[\'\"]/i',

            // Time-based blind
            'sleep' => '/\bsleep\s*\(\s*\d+\s*\)/i',
            'benchmark' => '/\bbenchmark\s*\(/i',
            'waitfor' => '/\bwaitfor\s+delay\b/i',
            'pg_sleep' => '/\bpg_sleep\s*\(/i',

            // Error-based
            'extractvalue' => '/\bextractvalue\s*\(/i',
            'updatexml' => '/\bupdatexml\s*\(/i',

            // Stacked queries
            'stacked_query' => '/;\s*(select|insert|update|delete|drop|create|alter|truncate)\b/i',

            // Common SQL keywords in suspicious context
            'select_from' => '/\bselect\b[\s\S]+?\bfrom\b/i',
            'insert_into' => '/\binsert\s+into\b/i',
            'update_set' => '/\bupdate\b[\s\S]+?\bset\b/i',
            'delete_from' => '/\bdelete\s+from\b/i',
            'drop_table' => '/\bdrop\s+(table|database|schema)\b/i',
            'truncate_table' => '/\btruncate\s+table\b/i',
            'alter_table' => '/\balter\s+table\b/i',
            'create_table' => '/\bcreate\s+(table|database|schema)\b/i',

            // Information schema
            'information_schema' => '/\binformation_schema\b/i',
            'sys_tables' => '/\bsys\.(tables|columns|objects)\b/i',
            'mysql_tables' => '/\bmysql\.(user|db)\b/i',

            // Hex encoding
            'hex_encoding' => '/0x[0-9a-f]+/i',

            // Char function
            'char_function' => '/\bchar\s*\(\s*\d+(\s*,\s*\d+)*\s*\)/i',
            'chr_function' => '/\bchr\s*\(\s*\d+\s*\)/i',

            // Concat functions
            'concat_function' => '/\bconcat\s*\(/i',
            'concat_ws' => '/\bconcat_ws\s*\(/i',
            'group_concat' => '/\bgroup_concat\s*\(/i',

            // Subquery
            'subquery' => '/\(\s*select\b/i',

            // Having/Group By injection
            'having_clause' => '/\bhaving\b[\s\S]+?[<>=]/i',
            'group_by' => '/\bgroup\s+by\b/i',
            'order_by_number' => '/\border\s+by\s+\d+/i',

            // Load file / Into outfile
            'load_file' => '/\bload_file\s*\(/i',
            'into_outfile' => '/\binto\s+(out|dump)file\b/i',

            // Quote manipulation
            'quote_escape' => '/[\'\"]\s*\+\s*[\'\"]|[\'\"]\s*\|\|\s*[\'\"]/i',
            'backslash_escape' => '/\\\'/i',

            // Null byte
            'null_terminator' => '/\x00/i',

            // SQL Server specific
            'exec_xp' => '/\bexec\s*(sp_|xp_)/i',
            'execute_immediate' => '/\bexecute\s+immediate\b/i',

            // NoSQL injection patterns
            'mongodb_operator' => '/\$(?:where|gt|lt|ne|eq|regex|or|and)\b/i',
            'mongodb_js' => '/\$where\s*:\s*[\'\"]/i',
        ];
    }
}
