import hashlib
import hmac

from .algorithm import Algorithm


class HMACAlgorithm(Algorithm):
    def __init__(self):
        super().__init__(
            {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        )

    def generate_signature(
        self, encoded_header: str, encoded_payload: str, algorithm: str, secret_key: str
    ) -> str:
        return hmac.new(
            secret_key.encode(),
            f"{encoded_header}.{encoded_payload}".encode(),
            self.supported_algorithms[algorithm],
        ).hexdigest()

    def verify_signature(
        self,
        encoded_header: str,
        encoded_payload: str,
        algorithm: str,
        signature: str,
        secret_key: str,
    ) -> bool:
        return hmac.compare_digest(
            signature,
            self.generate_signature(
                encoded_header, encoded_payload, algorithm, secret_key
            ),
        )
