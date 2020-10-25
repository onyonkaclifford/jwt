<?php

namespace JWT;

class VerificationException extends \Exception
{
}

class NbfException extends \Exception
{
}

class ExpException extends \Exception
{
}

class JWS
{
    public static $supported_algorithms = array(
        "HS256" => "SHA256",
        "HS384" => "SHA384",
        "HS512" => "SHA512");

    /**
     * @param array $data_map <p>map of claims, as an associative array</p>
     * @param string $key <p>secret key</p>
     * @param integer $nbf <p>not before, given as a Unix timestamp</p>
     * @param integer $exp_after <p>expire after how many milliseconds since time of issue</p>
     * @param string $algorithm <p>algorithm to use in signature generation</p>
     * @return string <p>jwt string</p>
     */
    public static function encode($data_map, $key, $nbf, $exp_after, $algorithm = "HS256")
    {
        static::checkAlgorithmSupport($algorithm);

        if (\count(\array_filter(\array_keys($data_map), "is_string")) === 0) {
            throw new \InvalidArgumentException("Data map needs to be an associative array");
        }

        $header = static::encodeHeader($algorithm);
        $payload = static::encodePayload($data_map, $nbf, $exp_after);
        $signature = static::encodeSignature($header, $payload, $algorithm, $key);

        return "$header.$payload.$signature";
    }

    /**
     * @param string $token <p>jwt string</p>
     * @param string $key <p>secret key</p>
     * @return string <p>map of claims</p>
     * @throws ExpException <p>jwt is expired</p>
     * @throws NbfException <p>jwt not yet active</p>
     * @throws VerificationException <p>jwt signature verification failed</p>
     */
    public static function decode($token, $key)
    {
        $token_segments = \explode(".", $token);
        $encoded_header = $token_segments[0];
        $encoded_payload = $token_segments[1];
        $encoded_signature = $token_segments[2];

        $header = static::decodeHeader($encoded_header);
        static::checkAlgorithmSupport($header->alg);

        if (!static::verifySignature($encoded_header, $encoded_payload, $encoded_signature, $header->alg, $key)) {
            throw new VerificationException("Signature verification failed");
        } else {
            $current_timestamp = time();
            $payload = static::decodePayload($encoded_payload);

            if ($current_timestamp < $payload->nbf) {
                throw new NbfException("Not yet active. Becomes active at " . $payload->nbf);
            } else if ($current_timestamp > $payload->exp) {
                throw new ExpException("Expired at " . $payload->exp);
            } else {
                return $payload->payload;
            }
        }
    }

    private static function checkAlgorithmSupport($algorithm)
    {
        if (!\array_key_exists($algorithm, static::$supported_algorithms)) {
            throw new \InvalidArgumentException(""
                . "$algorithm isn't supported. Accepts: "
                . \array_keys(static::$supported_algorithms));
        }
    }

    private static function encodeHeader($algorithm)
    {
        $ob = array("typ" => "JWT", "alg" => $algorithm);
        return static::urlSafeEncode($ob);
    }

    private static function decodeHeader($encoded_header)
    {
        return static::urlSafeDecode($encoded_header);
    }

    private static function encodePayload($data_map, $nbf, $exp_after)
    {
        $time = \time();

        $ob = new \stdClass();
        $ob->iat = $time;  // Issued at time
        $ob->nbf = $nbf;  // Not before
        $ob->exp = $time + $exp_after;  // Expiration
        $ob->payload = $data_map;

        return static::urlSafeEncode($ob);
    }

    private static function decodePayload($encoded_payload)
    {
        return static::urlSafeDecode($encoded_payload);
    }

    private static function encodeSignature($encoded_header, $encoded_payload, $algorithm, $key)
    {
        $hashed = \hash_hmac(static::$supported_algorithms[$algorithm], "$encoded_header.$encoded_payload", $key);
        return static::urlSafeEncode($hashed, false);
    }

    private static function verifySignature($encoded_header, $encoded_payload, $encoded_signature, $algorithm, $key)
    {
        $encoded_signature2 = static::encodeSignature($encoded_header, $encoded_payload, $algorithm, $key);
        return \hash_equals($encoded_signature, $encoded_signature2);
    }

    private static function urlSafeEncode($data, $encode_as_json = true)
    {
        if ($encode_as_json) {
            return \rtrim(\urlencode(\base64_encode(\json_encode($data))), "=");
        } else {
            return \rtrim(\urlencode(\base64_encode($data)));
        }
    }

    private static function urlSafeDecode($data)
    {
        return \json_decode(\base64_decode(\urldecode($data)));
    }
}
