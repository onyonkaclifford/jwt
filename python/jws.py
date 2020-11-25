import base64
import binascii
import hashlib
import hmac
import json
import time


class VerificationException(Exception):
    pass


class NbfException(Exception):
    pass


class ExpException(Exception):
    pass


class JWS:
    supported_algorithms = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512
    }

    @staticmethod
    def encode(data_map, key, nbf, exp_after, algorithm="HS256"):
        """
        :param data_map: map of claims, as a dict
        :param key: secret key
        :param nbf: not before, given as a Unix timestamp
        :param exp_after: expire after how many milliseconds since time of issue
        :param algorithm: algorithm to use in signature generation
        :return: jwt string
        """
        JWS.__check_algorithm_support(algorithm)

        if not isinstance(data_map, dict):
            raise TypeError("Data map needs to be a dict")

        header = JWS.__encode_header(algorithm)
        payload = JWS.__encode_payload(data_map, nbf, exp_after)
        signature = JWS.__encode_signature(header, payload, algorithm, key)

        return "{}.{}.{}".format(header, payload, signature)

    @staticmethod
    def decode(token, key):
        """
        :param token: jwt string
        :param key: secret key
        :return: map of claims
        """
        token_segments = token.split(".")
        encoded_header = token_segments[0]
        encoded_payload = token_segments[1]
        encoded_signature = token_segments[2]

        header = JWS.__decode_header(encoded_header)
        JWS.__check_algorithm_support(header["alg"])

        if not JWS.__verify_signature(encoded_header, encoded_payload, encoded_signature, header["alg"], key):
            raise VerificationException("Signature verification failed")
        else:
            current_timestamp = time.time()
            payload = JWS.__decode_payload(encoded_payload)

            if current_timestamp < payload["nbf"]:
                raise NbfException("Not yet active. Becomes active at %f" % payload["nbf"])
            elif current_timestamp > payload["exp"]:
                raise ExpException("Expired at %f" % payload["exp"])
            else:
                return payload["payload"]

    @staticmethod
    def __check_algorithm_support(algorithm):
        if algorithm not in JWS.supported_algorithms.keys():
            raise ValueError("{} not supported. Accepts: ".format(algorithm, JWS.supported_algorithms.keys()))

    @staticmethod
    def __encode_header(algorithm):
        ob = {"typ": "JWT", "alg": algorithm}
        return JWS.__url_safe_encode(ob)

    @staticmethod
    def __decode_header(encoded_header):
        return JWS.__url_safe_decode(encoded_header)

    @staticmethod
    def __encode_payload(data_map, nbf, exp_after):
        current_time = time.time()

        ob = {
            "iat": current_time,  # Issued at time
            "nbf": nbf,  # Not before
            "exp": current_time + exp_after,  # Expiration
            "payload": data_map
        }

        return JWS.__url_safe_encode(ob)

    @staticmethod
    def __decode_payload(encoded_payload):
        return JWS.__url_safe_decode(encoded_payload)

    @staticmethod
    def __encode_signature(encoded_header, encoded_payload, algorithm, key):
        hashed = hmac.new(
            key.encode(), "{}.{}".format(encoded_header, encoded_payload).encode(), JWS.supported_algorithms[algorithm]
        ).hexdigest()
        return JWS.__url_safe_encode(hashed, False)

    @staticmethod
    def __verify_signature(encoded_header, encoded_payload, encoded_signature, algorithm, key):
        encoded_signature2 = JWS.__encode_signature(encoded_header, encoded_payload, algorithm, key)
        return hmac.compare_digest(encoded_signature, encoded_signature2)

    @staticmethod
    def __url_safe_encode(data, encode_as_json=True):
        if encode_as_json:
            return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        else:
            return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

    @staticmethod
    def __url_safe_decode(data, max_iters=5):
        i = 0
        while True:
            i += 1
            try:
                decoded = json.loads(base64.urlsafe_b64decode(data))
                break
            except binascii.Error as e:
                if i >= max_iters:
                    raise e
                data += "="

        return decoded
