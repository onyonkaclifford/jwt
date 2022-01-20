import * as crypto from "crypto";
import { Algorithm } from "./algorithm.js";

export const HMACAlgorithm = function () {};

HMACAlgorithm.prototype = new Algorithm(
  { HS256: "sha256", HS384: "sha384", HS512: "sha512" },
  HMACAlgorithm
);

HMACAlgorithm.prototype.generateSignature = (
  encodedHeader,
  encodedPayload,
  algorithm,
  secretKey
) =>
  crypto
    .createHmac(
      HMACAlgorithm.prototype.supportedAlgorithms[algorithm],
      secretKey
    )
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("hex");

HMACAlgorithm.prototype.verifySignature = (
  encodedHeader,
  encodedPayload,
  algorithm,
  signature,
  secretKey
) =>
  crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(
      HMACAlgorithm.prototype.generateSignature(
        encodedHeader,
        encodedPayload,
        algorithm,
        secretKey
      )
    )
  );
