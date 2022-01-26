import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

/**
 * Generate a private and public RSA key pair, the default arguments are the recommended arguments to be passed to this
 * function
 * @param publicExponent a value of 3 or 65537 is recommended, though 65537 is chosen as the better recommendation
 * @param keySize a value that's a multiple of 256 and is greater than or equal to 2048 is recommended
 * @returns {{privateKey: KeyObject, publicKey: KeyObject}}
 */
export const generateRSAKeys = function (
  publicExponent = 65537,
  keySize = 2048
) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    publicExponent: publicExponent,
    modulusLength: keySize,
  });
  return { privateKey, publicKey };
};

/**
 * Save a private and public RSA key pair to a pem file
 * @param privateKey an RSA private key
 * @param publicKey an RSA public key
 * @param dirToSaveTo the directory to save the private and public RSA keys
 * @param nameOfKey name to identify the files the keys will be saved in
 * @param password password used during encryption of the private key
 */
export const savePrivateAndPublicKeys = function (
  privateKey,
  publicKey,
  dirToSaveTo,
  nameOfKey,
  password = null
) {
  const privateKeyString =
    password !== null
      ? privateKey.export({
          type: "pkcs8",
          format: "pem",
          cipher: "aes-256-cbc",
          passphrase: password,
        })
      : privateKey.export({
          type: "pkcs8",
          format: "pem",
        });
  const publicKeyString = publicKey.export({
    type: "spki",
    format: "pem",
  });

  fs.writeFileSync(
    path.join(dirToSaveTo, `${nameOfKey}-private.pem`),
    privateKeyString
  );
  fs.writeFileSync(
    path.join(dirToSaveTo, `${nameOfKey}-public.pem`),
    publicKeyString
  );
};

/**
 * Load a private and public RSA key pair from their respective pem files
 * @param pathToPrivateKey location of the private key
 * @param pathToPublicKey location of the public key
 * @param password password used during encryption of the private key
 * @returns {{privateKey: KeyObject, publicKey: KeyObject}}
 */
export const loadPrivateAndPublicKeys = function (
  pathToPrivateKey,
  pathToPublicKey,
  password = null
) {
  const privateKeyString = fs.readFileSync(pathToPrivateKey);
  const privateKey =
    password !== null
      ? crypto.createPrivateKey({
          key: privateKeyString,
          passphrase: password,
        })
      : crypto.createPrivateKey({
          key: privateKeyString,
        });
  const publicKey = loadPublicKey(pathToPublicKey);

  return { privateKey, publicKey };
};

/**
 * Load a public RSA key from a pem file
 * @param pathToPublicKey location of the public key
 * @returns {KeyObject}
 */
export const loadPublicKey = function (pathToPublicKey) {
  const publicKeyString = fs.readFileSync(pathToPublicKey);
  return crypto.createPublicKey({
    key: publicKeyString,
  });
};
