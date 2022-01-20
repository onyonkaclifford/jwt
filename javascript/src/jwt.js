import { HMACAlgorithm } from "./algorithms/hmac_algorithm.js";
import { RSAAlgorithm } from "./algorithms/rsa_algorithm.js";
import { encode, decode } from "./algorithms/url_safe_codec.js";

export const JWT = (() => {
  const ALGORITHM_CLASS_RESOLVER = { HS: HMACAlgorithm, RS: RSAAlgorithm };
  const SUPPORTED_ALGORITHMS = Object.keys(
    new HMACAlgorithm().supportedAlgorithms
  ).concat(Object.keys(new RSAAlgorithm().supportedAlgorithms));

  return {
    encode: (
      claims,
      secretKey,
      nbf,
      expAfter,
      iat = undefined,
      algorithm = "HS256"
    ) => {
      iat = iat === undefined ? Math.floor(Date.now() / 1000) : iat;

      let AlgorithmClass;

      try {
        AlgorithmClass = ALGORITHM_CLASS_RESOLVER[algorithm.slice(0, 2)];
      } catch (e) {
        throw new Error(
          `${algorithm} not supported. Accepts: ${SUPPORTED_ALGORITHMS}`
        );
      }

      const algorithmObject = new AlgorithmClass();

      if (!algorithmObject.isAlgorithmSupported(algorithm)) {
        throw new Error(
          `${algorithm} not supported. Accepts: ${SUPPORTED_ALGORITHMS}`
        );
      }

      const encodedHeader = encode({ typ: "JWT", alg: algorithm });
      const encodedPayload = encode({
        iat: iat,
        nbf: nbf,
        exp: iat + expAfter,
        claims: claims,
      });
      const signature = algorithmObject.generateSignature(
        encodedHeader,
        encodedPayload,
        algorithm,
        secretKey
      );
      const encodedSignature = encode(signature);

      return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
    },
    decode: (token, key) => {
      let encodedHeader;
      let encodedPayload;
      let encodedSignature;

      try {
        const tokenSegments = token.split(".");
        encodedHeader = tokenSegments[0];
        encodedPayload = tokenSegments[1];
        encodedSignature = tokenSegments[2];
      } catch (e) {
        throw new Error(
          "Token passed doesn't conform to the JWT format - header.payload.signature"
        );
      }

      const header = decode(encodedHeader);
      let algorithm;

      try {
        algorithm = header.alg;
      } catch (e) {
        throw new Error(
          `Token passed uses an unsupported algorithm. Supported algorithms: ${SUPPORTED_ALGORITHMS}`
        );
      }

      const AlgorithmClass = ALGORITHM_CLASS_RESOLVER[algorithm.slice(0, 2)];
      const algorithmObject = new AlgorithmClass();

      if (
        !algorithmObject.verifySignature(
          encodedHeader,
          encodedPayload,
          algorithm,
          decode(encodedSignature),
          key
        )
      ) {
        throw new Error("Signature verification failed");
      }

      const currentTimestamp = Math.floor(Date.now() / 1000);
      const payload = decode(encodedPayload);

      if (currentTimestamp < payload.nbf) {
        throw new Error(`Not yet active. Becomes active at ${payload.nbf}`);
      } else if (currentTimestamp > payload.exp) {
        throw new Error(`Expired at ${payload.exp}`);
      }

      return payload.claims;
    },
  };
})();
