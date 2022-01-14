import time
from typing import Any, Union

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .algorithms import Algorithm, HMACAlgorithm, RSAAlgorithm, url_safe_codec


class JWT:
    ALGORITHM_CLASS_RESOLVER = {"HS": HMACAlgorithm, "RS": RSAAlgorithm}
    SUPPORTED_ALGORITHMS = {
        *HMACAlgorithm().supported_algorithms.keys(),
        *RSAAlgorithm().supported_algorithms.keys(),
    }

    @staticmethod
    def encode(
        claims: Any,
        secret_key: Union[str, RSAPrivateKey],
        nbf: float,
        exp_after: int,
        iat: float = time.time(),
        algorithm: str = "HS256",
    ) -> str:
        """Generate a JWT

        :param claims: data to be stored in the JWT, preferably needs to be passed as a map-like object such as a dict
        :param secret_key: key to use during signature generation
        :param nbf: 'not before' time claim
        :param exp_after: 'expire after' time claim
        :param iat: 'issued at' time claim
        :param algorithm: algorithms to use during signature generation
        :return: a JSON web token
        """
        try:
            algorithm_class = JWT.ALGORITHM_CLASS_RESOLVER[algorithm[:2]]
        except KeyError as e:
            raise ValueError(
                f"{algorithm} not supported. Accepts: {JWT.SUPPORTED_ALGORITHMS}"
            ) from e

        algorithm_object: Algorithm = algorithm_class()

        if not algorithm_object.is_algorithm_supported(algorithm):
            raise ValueError(
                f"{algorithm} not supported. Accepts: {JWT.SUPPORTED_ALGORITHMS}"
            )

        encoded_header = url_safe_codec.encode({"typ": "JWT", "alg": algorithm})
        encoded_payload = url_safe_codec.encode(
            {"iat": iat, "nbf": nbf, "exp": iat + exp_after, "claims": claims}
        )
        encoded_signature = url_safe_codec.encode(
            algorithm_object.generate_signature(
                encoded_header, encoded_payload, algorithm, secret_key
            )
        )

        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    @staticmethod
    def decode(token: str, key: Union[str, RSAPublicKey]):
        """Get the claims stored in a JWT

        :param token: a JSON web token
        :param key: key to use during signature verification
        :return: claims
        """
        try:
            token_segments = token.split(".")
            encoded_header = token_segments[0]
            encoded_payload = token_segments[1]
            encoded_signature = token_segments[2]
        except IndexError as e:
            raise ValueError(
                "Token passed doesn't conform to the JWT format - header.payload.signature"
            ) from e

        header = url_safe_codec.decode(encoded_header)

        try:
            algorithm = header["alg"]
        except KeyError as e:
            raise ValueError(
                f"Token passed uses an unsupported algorithm. Supported algorithms: {JWT.SUPPORTED_ALGORITHMS}"
            ) from e

        algorithm_class = JWT.ALGORITHM_CLASS_RESOLVER[algorithm[:2]]
        algorithm_object: Algorithm = algorithm_class()

        if not algorithm_object.verify_signature(
            encoded_header,
            encoded_payload,
            algorithm,
            url_safe_codec.decode(encoded_signature),
            key,
        ):
            raise ValueError("Signature verification failed")

        current_timestamp = time.time()
        payload = url_safe_codec.decode(encoded_payload)

        if current_timestamp < payload["nbf"]:
            raise ValueError(f"Not yet active. Becomes active at {payload['nbf']}")
        elif current_timestamp > payload["exp"]:
            raise ValueError(f"Expired at {payload['exp']}")

        return payload["claims"]
