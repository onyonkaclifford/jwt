import base64
import hashlib
import hmac
import json
import time
from typing import Any, Union


class JWS:
    supported_algorithms = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512
    }

    @staticmethod
    def encode(
            claims: Any, key: str, nbf: float, exp_after: int, iat: float = time.time(), algorithm: str = "HS256"
    ) -> str:
        """Store data in a token that's signed and encoded as a JWS

        >>> jwt = JWS.encode({"a": "claim"}, "secret key", 421915.82036, 300000)
        >>> assert len(jwt.split(".")) == 3

        :param claims: data to be stored in the token
        :param key: secret key
        :param nbf: not before, given as a Unix timestamp
        :param exp_after: expire after how many milliseconds since time of issue
        :param iat: issued at, given as a Unix timestamp
        :param algorithm: algorithm to use in signature generation
        :return: token
        :raise ValueError: algorithm passed is not supported
        """
        if not JWS.__is_algorithm_supported(algorithm):
            raise ValueError("{} not supported. Accepts: ".format(algorithm, JWS.supported_algorithms.keys()))

        header = JWS.__encode_header(algorithm)
        payload = JWS.__encode_payload(claims, iat, nbf, exp_after)
        signature = JWS.__encode_signature(header, payload, algorithm, key)

        return "{}.{}.{}".format(header, payload, signature)

    @staticmethod
    def decode(token, key):
        """Get data stored in token

        >>> jwt = JWS.encode({"a": "claim"}, "secret key", 421915.82036, 300000)
        >>> claims = JWS.decode(jwt, "secret key")
        >>> assert claims == {"a": "claim"}

        :param token: token string
        :param key: secret key
        :return: data stored in token
        :raise ValueError: algorithm passed is not supported |
            signature verification failed |
            token not yet active |
            token has expired
        """
        token_segments = token.split(".")
        encoded_header = token_segments[0]
        encoded_payload = token_segments[1]
        encoded_signature = token_segments[2]

        header = JWS.__decode_header(encoded_header)

        if not JWS.__is_algorithm_supported(header["alg"]):
            raise ValueError("{} not supported. Accepts: ".format(header["alg"], JWS.supported_algorithms.keys()))

        if not JWS.__verify_signature(encoded_header, encoded_payload, encoded_signature, header["alg"], key):
            raise ValueError("Signature verification failed")

        current_timestamp = time.time()
        payload = JWS.__decode_payload(encoded_payload)

        if current_timestamp < payload["nbf"]:
            raise ValueError("Not yet active. Becomes active at %f" % payload["nbf"])
        elif current_timestamp > payload["exp"]:
            raise ValueError("Expired at %f" % payload["exp"])
        else:
            return payload["claims"]

    @staticmethod
    def __is_algorithm_supported(algorithm: str) -> bool:
        return True if algorithm in JWS.supported_algorithms.keys() else False

    @staticmethod
    def __encode_header(algorithm: str) -> str:
        ob = {"typ": "JWT", "alg": algorithm}
        return JWS.__url_safe_encode(ob)

    @staticmethod
    def __decode_header(encoded_header: str) -> dict:
        return JWS.__url_safe_decode(encoded_header)

    @staticmethod
    def __encode_payload(claims: Any, iat: float, nbf: float, exp_after: int) -> str:
        ob = {"iat": iat, "nbf": nbf, "exp": iat + exp_after, "claims": claims}
        return JWS.__url_safe_encode(ob)

    @staticmethod
    def __decode_payload(encoded_payload: str) -> dict:
        return JWS.__url_safe_decode(encoded_payload)

    @staticmethod
    def __encode_signature(encoded_header: str, encoded_payload: str, algorithm: str, key: str) -> str:
        hashed = hmac.new(
            key.encode(), "{}.{}".format(encoded_header, encoded_payload).encode(), JWS.supported_algorithms[algorithm]
        ).hexdigest()
        return JWS.__url_safe_encode(hashed)

    @staticmethod
    def __verify_signature(
            encoded_header: str, encoded_payload: str, encoded_signature: str, algorithm: str, key: str
    ) -> bool:
        encoded_signature2 = JWS.__encode_signature(encoded_header, encoded_payload, algorithm, key)
        return hmac.compare_digest(encoded_signature, encoded_signature2)

    @staticmethod
    def __url_safe_encode(data: Union[dict, str]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    @staticmethod
    def __url_safe_decode(data: str) -> Union[dict, str]:
        needs_padding = len(data) % 4

        if needs_padding:
            padding_size = 4 - needs_padding
            data += "=" * padding_size

        decoded = json.loads(base64.urlsafe_b64decode(data).decode())

        return decoded
