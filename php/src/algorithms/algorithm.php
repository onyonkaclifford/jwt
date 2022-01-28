<?php

namespace JWT\algorithms;

abstract class Algorithm {
    public array $supportedAlgorithms;

    public function __construct(array $supportedAlgorithms) {
        $this->supportedAlgorithms = $supportedAlgorithms;
    }

    abstract function generateSignature(string $encodedHeader, string $encodedPayload, string $algorithm, mixed $key): string;

    abstract function verifySignature(string $encodedHeader, string $encodedPayload, string $algorithm, string $signature, mixed $key): bool;

    public function isAlgorithmSupported(string $algorithm): bool {
        return in_array($algorithm, array_keys($this->supportedAlgorithms));
    }
}
