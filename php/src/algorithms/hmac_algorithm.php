<?php

namespace JWT\algorithms;

require_once("algorithm.php");

class HMACAlgorithm extends Algorithm {
    public function __construct() {
        parent::__construct(array("HS256" => "SHA256", "HS384" => "SHA384", "HS512" => "SHA512"));
    }

    public function generateSignature(string $encodedHeader, string $encodedPayload, string $algorithm, mixed $key): string {
        return hash_hmac($this->supportedAlgorithms[$algorithm], "$encodedHeader.$encodedPayload", $key);
    }

    public function verifySignature(string $encodedHeader, string $encodedPayload, string $algorithm, string $signature, mixed $key): bool {
        return hash_equals($signature, $this->generateSignature($encodedHeader, $encodedPayload, $algorithm, $key));
    }
}
