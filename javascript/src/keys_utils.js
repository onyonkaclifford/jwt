import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

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

export const loadPublicKey = function (pathToPublicKey) {
  const publicKeyString = fs.readFileSync(pathToPublicKey);
  return crypto.createPublicKey({
    key: publicKeyString,
  });
};
