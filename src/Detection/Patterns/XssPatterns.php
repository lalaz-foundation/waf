<?php

declare(strict_types=1);

namespace Lalaz\Waf\Detection\Patterns;

use Lalaz\Waf\Detection\ThreatType;

/**
 * XSS (Cross-Site Scripting) detection patterns.
 *
 * @package lalaz/waf
 */
final class XssPatterns extends PatternSet
{
    public function getThreatType(): ThreatType
    {
        return ThreatType::XSS;
    }

    public function getPatterns(): array
    {
        return [
            // Script tags
            'script_tag' => '/<script[\s\S]*?>[\s\S]*?<\/script>/i',
            'script_tag_open' => '/<script[^>]*>/i',

            // Event handlers
            'event_handler' => '/\bon\w+\s*=\s*["\']?[^"\']*["\']?/i',
            'event_handler_encoded' => '/\bon\w+\s*&#?[\w]+;?=/i',

            // JavaScript protocol
            'javascript_protocol' => '/javascript\s*:/i',
            'vbscript_protocol' => '/vbscript\s*:/i',
            'data_protocol' => '/data\s*:[^,]*base64/i',

            // Expression/eval
            'expression' => '/expression\s*\(/i',
            'eval' => '/\beval\s*\(/i',
            'function_constructor' => '/\bFunction\s*\(/i',

            // DOM manipulation
            'document_cookie' => '/document\s*\.\s*cookie/i',
            'document_location' => '/document\s*\.\s*location/i',
            'document_write' => '/document\s*\.\s*write/i',
            'inner_html' => '/\.innerHTML\s*=/i',
            'outer_html' => '/\.outerHTML\s*=/i',

            // Window object
            'window_location' => '/window\s*\.\s*location/i',
            'window_open' => '/window\s*\.\s*open\s*\(/i',

            // Encoded scripts
            'encoded_script' => '/&#x?[0-9a-f]+;?\s*&#x?[0-9a-f]+;?\s*&#x?[0-9a-f]+;?/i',
            'unicode_escape' => '/\\\\u00[0-9a-f]{2}/i',

            // SVG/XML vectors
            'svg_onload' => '/<svg[^>]*\s+onload\s*=/i',
            'svg_script' => '/<svg[\s\S]*?<script/i',
            'xml_entity' => '/<!ENTITY\s+/i',

            // Object/embed/iframe
            'object_tag' => '/<object[^>]*>/i',
            'embed_tag' => '/<embed[^>]*>/i',
            'iframe_tag' => '/<iframe[^>]*>/i',
            'frame_tag' => '/<frame[^>]*>/i',

            // Style-based XSS
            'style_expression' => '/<style[^>]*>[\s\S]*expression\s*\(/i',
            'style_import' => '/@import\s+/i',
            'style_behavior' => '/behavior\s*:\s*url\s*\(/i',

            // Meta refresh
            'meta_refresh' => '/<meta[^>]*http-equiv\s*=\s*["\']?refresh/i',

            // Form hijacking
            'form_action' => '/<form[^>]*action\s*=\s*["\']?javascript:/i',

            // Base tag injection
            'base_tag' => '/<base[^>]*href/i',

            // Link stylesheet
            'link_tag' => '/<link[^>]*rel\s*=\s*["\']?stylesheet/i',

            // Template injection
            'template_injection' => '/\{\{\s*constructor\s*\}\}/i',
            'angular_expression' => '/\{\{.*?\}\}/i',
        ];
    }
}
