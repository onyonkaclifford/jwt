<?php

namespace JWT;

require __DIR__ . '/../vendor/autoload.php';

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

function generateRSAKeys(int $publicExponent = 65537, int $keySize = 2048): array {
    RSA::setExponent($publicExponent);
    $privateKey = RSA::createKey($keySize);
    $publicKey = $privateKey->getPublicKey();
    return array($privateKey, $publicKey);
}

function savePrivateAndPublicKeys(RSA\PrivateKey $privateKey, string $dirToSaveTo, string $nameOfKey, string $password = null) {
    $privateKeyString = $password !== null ? $privateKey->withPassword($password)->toString("PKCS8") : $privateKey->toString("PKCS8");
    $publicKeyString = $privateKey->getPublicKey()->toString("PKCS8");

    file_put_contents("$dirToSaveTo/$nameOfKey-private.pem", $privateKeyString);
    file_put_contents("$dirToSaveTo/$nameOfKey-public.pem", $publicKeyString);
}

function loadPrivateAndPublicKeys(string $pathToPrivateKey, string $password = null): array {
    $privateKey = $password !== null ? PublicKeyLoader::load(file_get_contents($pathToPrivateKey), $password) : PublicKeyLoader::load(file_get_contents($pathToPrivateKey));
    $publicKey = $privateKey->getPublicKey();

    return array($privateKey, $publicKey);
}

function loadPublicKey(string $pathToPublicKey): AsymmetricKey {
    return PublicKeyLoader::load(file_get_contents($pathToPublicKey));
}
