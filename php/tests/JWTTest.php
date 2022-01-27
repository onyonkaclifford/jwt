<?php

require_once("src/jwt.php");
require_once("src/keys_utils.php");

use PHPUnit\Framework\TestCase;
use phpseclib3\Crypt\RSA;
use JWT\JWT;
use function JWT\generateRSAKeys,
    JWT\savePrivateAndPublicKeys,
    JWT\loadPrivateAndPublicKeys,
    JWT\loadPublicKey;

class JWTTest extends TestCase {
    public function testRsaKeysGenerationAndSaving(): void {
        $keys = generateRSAKeys();
        $privateKey = $keys[0];
        $publicKey = $keys[1];
        $this->assertInstanceOf(RSA\PrivateKey::class, $privateKey);
        $this->assertInstanceOf(RSA\PublicKey::class, $publicKey);

        savePrivateAndPublicKeys($privateKey, ".", "test_key");
        $pathToSavedPrivateKey = "./test_key-private.pem";
        $pathToSavedPublicKey = "./test_key-public.pem";
        $this->assertTrue(file_exists($pathToSavedPrivateKey));
        $this->assertTrue(file_exists($pathToSavedPublicKey));

        unlink($pathToSavedPrivateKey);
        unlink($pathToSavedPublicKey);
    }

    public function testRsaKeysLoading(): void {
        $pathToPrivateKey = "tests/test_data/key-private.pem";
        $pathToPublicKey = "tests/test_data/key-public.pem";

        $keys = loadPrivateAndPublicKeys($pathToPrivateKey, "password");
        $privateKey = $keys[0];
        $publicKey = $keys[1];
        $this->assertInstanceOf(RSA\PrivateKey::class, $privateKey);
        $this->assertInstanceOf(RSA\PublicKey::class, $publicKey);

        $publicKey2 = loadPublicKey($pathToPublicKey);
        $this->assertInstanceOf(RSA\PublicKey::class, $publicKey2);
    }

    public function testHMAC(): void {
        $sampleClaims = array("sample" => "claim");
        $correctKey = "secret key";
        $wrongKey = "wrong key";

        $token = JWT::encode($sampleClaims, $correctKey, 235.45, 300000);
        $this->assertSame(count(explode(".", $token)), 3);

        $claims = JWT::decode($token, $correctKey);
        $this->assertSame($claims, $sampleClaims);

        $this->expectException(UnexpectedValueException::class);
        JWT::decode($token, $wrongKey);
    }

    public function testRSA(): void {
        $sampleClaims = array("sample" => "claim");
        $keys = generateRSAKeys();
        $keys2 = generateRSAKeys();
        $privateKey = $keys[0];
        $correctPublicKey = $keys[1];
        $wrongPublicKey = $keys2[1];

        $token = JWT::encode($sampleClaims, $privateKey, 235.45, 300000, null, "RS256");
        $this->assertSame(count(explode(".", $token)), 3);

        $claims = JWT::decode($token, $correctPublicKey);
        $this->assertSame($claims, $sampleClaims);

        $this->expectException(UnexpectedValueException::class);
        JWT::decode($token, $wrongPublicKey);
        }
}
