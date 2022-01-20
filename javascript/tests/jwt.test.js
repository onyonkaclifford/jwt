/* eslint-disable no-unused-vars */
import { jest } from "@jest/globals"; // Don't delete! This is required when testing ES modules!
/* eslint-enable no-unused-vars */
import * as fs from "fs";
import * as crypto from "crypto";
import * as path from "path";
import { JWT } from "../src/jwt.js";
import {
  generateRSAKeys,
  savePrivateAndPublicKeys,
  loadPrivateAndPublicKeys,
  loadPublicKey,
} from "../src/keys_utils.js";

test("Test RSA keys generation and saving", () => {
  const { privateKey, publicKey } = generateRSAKeys();
  expect(privateKey).toBeInstanceOf(crypto.KeyObject);
  expect(publicKey).toBeInstanceOf(crypto.KeyObject);

  savePrivateAndPublicKeys(privateKey, publicKey, ".", "test_key");
  const pathToSavedPrivateKey = path.join(".", "test_key-private.pem");
  const pathToSavedPublicKey = path.join(".", "test_key-public.pem");
  expect(fs.existsSync(pathToSavedPrivateKey)).toBeTruthy();
  expect(fs.existsSync(pathToSavedPublicKey)).toBeTruthy();

  fs.unlinkSync(pathToSavedPrivateKey);
  fs.unlinkSync(pathToSavedPublicKey);
});

test("Test RSA keys loading", () => {
  const pathToPrivateKey = path.join("tests", "test_data", "key-private.pem");
  const pathToPublicKey = path.join("tests", "test_data", "key-public.pem");

  const { privateKey, publicKey } = loadPrivateAndPublicKeys(
    pathToPrivateKey,
    pathToPublicKey
  );
  expect(privateKey).toBeInstanceOf(crypto.KeyObject);
  expect(publicKey).toBeInstanceOf(crypto.KeyObject);

  const publicKeyOnly = loadPublicKey(pathToPublicKey);
  expect(publicKeyOnly).toBeInstanceOf(crypto.KeyObject);
});

test("Test JWT (HMAC)", () => {
  const sampleClaims = { sample: "claim" };
  const correctKey = "secret key";
  const wrongKey = "wrong key";

  const token = JWT.encode(sampleClaims, correctKey, 235.45, 300000);
  expect(token.split(".").length).toBe(3);

  const claims = JWT.decode(token, correctKey);
  expect(claims).toStrictEqual(sampleClaims);

  expect(() => JWT.decode(token, wrongKey)).toThrowError(
    "Signature verification failed"
  );
});

test("Test JWT (RSA)", () => {
  const sampleClaims = { sample: "claim" };
  const { privateKey, publicKey } = generateRSAKeys();

  const token = JWT.encode(
    sampleClaims,
    privateKey,
    235.45,
    300000,
    undefined,
    "RS256"
  );
  expect(token.split(".").length).toBe(3);

  const claims = JWT.decode(token, publicKey);
  expect(claims).toStrictEqual(sampleClaims);
});
