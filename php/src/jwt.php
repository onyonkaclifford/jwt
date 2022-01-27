<?php

namespace JWT;

require_once("algorithms/hmac_algorithm.php");
require_once("algorithms/rsa_algorithm.php");
require_once("algorithms/url_safe_codec.php");

use UnexpectedValueException;
use phpseclib3\Crypt\RSA;
use JWT\algorithms\HMACAlgorithm,
    JWT\algorithms\RSAAlgorithm;
use function JWT\algorithms\encode as urlSafeEncode,
    JWT\algorithms\decode as urlSafeDecode;

class JWT {
    private static array $algorithmClassResolver;
    private static array $supportedAlgorithms;

    private function __construct() {}

    private static function init(): void {
        static::$algorithmClassResolver = array("HS" => "JWT\algorithms\HMACAlgorithm", "RS" => "JWT\algorithms\RSAAlgorithm");
        static::$supportedAlgorithms = array_merge(array_keys((new HMACAlgorithm())->supportedAlgorithms), array_keys((new RSAAlgorithm())->supportedAlgorithms));
    }

    public static function encode(array $claims, string|RSA\PrivateKey $secretKey, float $nbf, float $expAfter, float $iat = null, string $algorithm = "HS256"): string {
        static::init();

        $iat = $iat !== null ? $iat : time();

        if (!in_array($algorithm, static::$supportedAlgorithms)) {
            $supportedAlgorithms = implode(", ", static::$supportedAlgorithms);
            throw new UnexpectedValueException("$algorithm not supported. Accepts: $supportedAlgorithms");
        }

        $AlgorithmClass = static::$algorithmClassResolver[substr($algorithm, 0, 2)];
        $algorithmObject = new $AlgorithmClass();

        if (!$algorithmObject->isAlgorithmSupported($algorithm)) {
            $supportedAlgorithms = implode(", ", static::$supportedAlgorithms);
            throw new UnexpectedValueException("$algorithm not supported. Accepts: $supportedAlgorithms");
        }

        $encodedHeader = urlSafeEncode(array("typ" => "JWT", "alg" => $algorithm));
        $encodedPayload = urlSafeEncode( array_merge(array("iat" => $iat, "nbf" => $nbf, "exp" => $iat + $expAfter), $claims));
        $encodedSignature = urlSafeEncode(
            $algorithmObject->generateSignature($encodedHeader, $encodedPayload, $algorithm, $secretKey)
        );

        return "$encodedHeader.$encodedPayload.$encodedSignature";
    }

    public static function decode(string $token, string|RSA\PublicKey $key): array {
        static::init();

        $tokenSegments = explode(".", $token);

        if (count($tokenSegments) !== 3) {
            throw new UnexpectedValueException("Token passed doesn't conform to the JWT format - header.payload.signature");
        }

        $encodedHeader = $tokenSegments[0];
        $encodedPayload = $tokenSegments[1];
        $encodedSignature = $tokenSegments[2];
        $header = urlSafeDecode($encodedHeader);

        if (!property_exists($header, "alg")) {
            $supportedAlgorithms = implode(", ", static::$supportedAlgorithms);
            throw new UnexpectedValueException("Token passed uses an unsupported algorithm. Supported algorithms: $supportedAlgorithms");
        }

        $algorithm = $header->alg;
        $AlgorithmClass = static::$algorithmClassResolver[substr($algorithm, 0, 2)];
        $algorithmObject = new $AlgorithmClass();

        if (!$algorithmObject->verifySignature($encodedHeader, $encodedPayload, $algorithm, urlSafeDecode($encodedSignature), $key)) {
            throw new UnexpectedValueException("Signature verification failed");
        }

        $currentTimestamp = time();
        $payload = (array) urlSafeDecode($encodedPayload);
        $claimsKeys = array_keys($payload);

        if (in_array("nbf", $claimsKeys) && $currentTimestamp < $payload["nbf"]) {
            $nbf = $payload["nbf"];
            throw new UnexpectedValueException("Not yet active. Becomes active at $nbf");
        } elseif (in_array("exp", $claimsKeys) && $currentTimestamp > $payload["exp"]) {
            $exp = $payload["exp"];
            throw new UnexpectedValueException("Expired at $exp");
        }

        foreach (["iat", "nbf", "exp"] as $i) {
            unset($payload[$i]);
        }

        return $payload;
    }
}
