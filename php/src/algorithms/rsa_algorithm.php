<?php

namespace JWT\algorithms;

require __DIR__ . '/../../vendor/autoload.php';
require_once("algorithm.php");

use phpseclib3\Crypt\RSA;

class RSAAlgorithm extends Algorithm {
    public function __construct() {
        parent::__construct(array("RS256" => "sha256", "RS384" => "sha384", "RS512" => "sha512"));
    }

    public function generateSignature(string $encodedHeader, string $encodedPayload, string $algorithm, mixed $privateKey): string {
        return bin2hex($privateKey->withHash($this->supportedAlgorithms[$algorithm])
            ->withMGFHash($this->supportedAlgorithms[$algorithm])
            ->withPadding(RSA::SIGNATURE_PSS)
            ->sign("$encodedHeader.$encodedPayload"));
    }

    public function verifySignature(string $encodedHeader, string $encodedPayload, string $algorithm, string $signature, mixed $publicKey): bool {
        return $publicKey->withHash($this->supportedAlgorithms[$algorithm])
            ->withMGFHash($this->supportedAlgorithms[$algorithm])
            ->withPadding(RSA::SIGNATURE_PSS)
            ->verify("$encodedHeader.$encodedPayload", hex2bin($signature));
    }
}
