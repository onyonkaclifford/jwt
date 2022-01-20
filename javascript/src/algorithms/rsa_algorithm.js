import * as crypto from "crypto";
import { Algorithm } from "./algorithm.js";

export const RSAAlgorithm = function () {};

RSAAlgorithm.prototype = new Algorithm(
  { RS256: "sha256", RS384: "sha384", RS512: "sha512" },
  RSAAlgorithm
);

RSAAlgorithm.prototype.generateSignature = (
  encodedHeader,
  encodedPayload,
  algorithm,
  privateKey
) =>
  crypto
    .sign(
      RSAAlgorithm.prototype.supportedAlgorithms[algorithm],
      Buffer.from(`${encodedHeader}.${encodedPayload}`),
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }
    )
    .toString("hex");

RSAAlgorithm.prototype.verifySignature = (
  encodedHeader,
  encodedPayload,
  algorithm,
  signature,
  publicKey
) =>
  crypto.verify(
    RSAAlgorithm.prototype.supportedAlgorithms[algorithm],
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
    Buffer.from(signature, "hex")
  );
