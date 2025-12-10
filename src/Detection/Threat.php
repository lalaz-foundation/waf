<?php

declare(strict_types=1);

namespace Lalaz\Waf\Detection;

/**
 * Represents a detected threat.
 *
 * @package lalaz/waf
 */
final class Threat
{
    public function __construct(
        public readonly ThreatType $type,
        public readonly string $payload,
        public readonly string $location,
        public readonly string $pattern,
        public readonly ?string $field = null,
    ) {
    }

    /**
     * Get threat as array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type->value,
            'label' => $this->type->label(),
            'severity' => $this->type->severity(),
            'payload' => $this->payload,
            'location' => $this->location,
            'field' => $this->field,
            'pattern' => $this->pattern,
        ];
    }

    /**
     * Create from array.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            type: ThreatType::from($data['type']),
            payload: $data['payload'],
            location: $data['location'],
            pattern: $data['pattern'],
            field: $data['field'] ?? null,
        );
    }
}
